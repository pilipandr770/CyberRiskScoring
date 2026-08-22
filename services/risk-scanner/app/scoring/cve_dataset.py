"""
Local CVE cache — sparse-cloned from cvelistV5 (official CVE JSON 5.0
records), refreshed periodically. Product/version -> CVE matching for
recon/Shodan findings uses this instead of live per-lookup NVD API calls,
which are rate-limited (5 req/30s without a key) and too slow to run once
per detected service during a scan.

Only a capped, most-relevant subset (CVE_CVELIST_MAX_ROWS) is kept in the
final index: entries with a scored CVSS first, most recently published
within each group. The full sparse clone stays on disk as the source the
cache is rebuilt from on each refresh, not something queried directly.
"""

import csv
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone

from app.config import (
    CVE_CACHE_CSV, CVE_CACHE_REPO_DIR, CVE_CSV_REFRESH_HOURS,
    CVE_CSV_REMOTE_URL, CVE_CVELIST_MAX_ROWS, CVE_CVELIST_YEARS_BACK,
)

log = logging.getLogger("cve_dataset")

_index: list[dict] | None = None
# version_ranges: JSON-encoded list of {"start", "end", "end_type"} — the
# raw CVE JSON 5.0 "versions" constraints for this product, kept so match()
# can actually check whether a *given* version falls in the affected range
# instead of only reordering by exact-string match. description: truncated
# CNA description text, so the LLM has something real to describe instead
# of just a bare CVE ID.
_FIELDNAMES = [
    "cve_id", "vendor", "product", "version", "cvss_score", "published",
    "version_ranges", "description",
]
_MAX_DESCRIPTION_CHARS = 500


def _years_back_list() -> list[str]:
    current_year = datetime.now(timezone.utc).year
    return [str(y) for y in range(current_year - CVE_CVELIST_YEARS_BACK + 1, current_year + 1)]


def _run_git(args: list[str], cwd: str | None = None, timeout: int = 3600) -> None:
    subprocess.run(
        ["git"] + args, cwd=cwd, check=True, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def _ensure_repo() -> None:
    years = _years_back_list()
    paths = [f"cves/{y}" for y in years]
    if not os.path.exists(os.path.join(CVE_CACHE_REPO_DIR, ".git")):
        os.makedirs(os.path.dirname(CVE_CACHE_REPO_DIR), exist_ok=True)
        log.info("cve_dataset: cloning cvelistV5 (sparse, years=%s) — first run, this takes a while", years)
        _run_git([
            "clone", "--depth", "1", "--filter=blob:none", "--sparse",
            CVE_CSV_REMOTE_URL, CVE_CACHE_REPO_DIR,
        ])
        _run_git(["sparse-checkout", "set"] + paths, cwd=CVE_CACHE_REPO_DIR)
    else:
        log.info("cve_dataset: refreshing existing sparse clone")
        _run_git(["sparse-checkout", "set"] + paths, cwd=CVE_CACHE_REPO_DIR)
        _run_git(["fetch", "--depth", "1", "origin"], cwd=CVE_CACHE_REPO_DIR)
        _run_git(["reset", "--hard", "origin/HEAD"], cwd=CVE_CACHE_REPO_DIR)


def _extract_description(cna: dict) -> str:
    for d in cna.get("descriptions") or []:
        if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
            return str(d["value"])[:_MAX_DESCRIPTION_CHARS]
    for d in cna.get("descriptions") or []:
        if d.get("value"):
            return str(d["value"])[:_MAX_DESCRIPTION_CHARS]
    return ""


def _extract_version_ranges(versions: list[dict]) -> list[dict]:
    """Every 'affected' constraint for one product, kept as (start, end,
    end_type) so match() can later check a *given* version against the
    actual range instead of just the single string this used to collapse
    everything down to."""
    ranges = []
    for v in versions:
        if v.get("status") != "affected":
            continue
        start = v.get("version") or ""
        if v.get("lessThan"):
            ranges.append({"start": start, "end": v["lessThan"], "end_type": "lessThan"})
        elif v.get("lessThanOrEqual"):
            ranges.append({"start": start, "end": v["lessThanOrEqual"], "end_type": "lessThanOrEqual"})
        elif start:
            # A single fixed version with no upper bound in this record —
            # treat it as affecting just that exact version.
            ranges.append({"start": start, "end": start, "end_type": "lessThanOrEqual"})
    return ranges


def _extract_rows(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    meta = data.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id or str(meta.get("state", "")).upper() == "REJECTED":
        return []

    cna = (data.get("containers") or {}).get("cna") or {}
    affected = cna.get("affected") or []
    metrics = cna.get("metrics") or []

    cvss_score = None
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            block = m.get(key)
            if isinstance(block, dict) and "baseScore" in block:
                cvss_score = block["baseScore"]
                break
        if cvss_score is not None:
            break

    published = meta.get("datePublished", "") or ""
    description = _extract_description(cna)

    if not affected:
        return [{"cve_id": cve_id, "vendor": "", "product": "", "version": "",
                  "cvss_score": cvss_score, "published": published,
                  "version_ranges": "[]", "description": description}]

    rows = []
    for a in affected:
        vendor = str(a.get("vendor") or "").strip()
        product = str(a.get("product") or "").strip()
        if not product:
            continue
        raw_versions = a.get("versions") or []
        version_ranges = _extract_version_ranges(raw_versions)
        # Keep the old single-string field too — still used as the
        # "exact-match reorder" hint and shown in the technical appendix.
        version_str = ""
        for v in raw_versions:
            if v.get("status") == "affected":
                version_str = v.get("version") or v.get("lessThan") or ""
                break
        rows.append({
            "cve_id": cve_id, "vendor": vendor, "product": product,
            "version": version_str, "cvss_score": cvss_score, "published": published,
            "version_ranges": json.dumps(version_ranges), "description": description,
        })
    return rows


def _refresh_sync() -> None:
    _ensure_repo()

    rows: list[dict] = []
    years = _years_back_list()
    for y in years:
        year_dir = os.path.join(CVE_CACHE_REPO_DIR, "cves", y)
        if not os.path.isdir(year_dir):
            continue
        for root, _dirs, files in os.walk(year_dir):
            for fn in files:
                if fn.endswith(".json"):
                    rows.extend(_extract_rows(os.path.join(root, fn)))

    # Stable sort twice: most recent first, then scored-CVSS entries first —
    # net effect is "scored, most recent" at the top of each group.
    rows.sort(key=lambda r: r["published"], reverse=True)
    rows.sort(key=lambda r: r["cvss_score"] is None)
    capped = rows[:CVE_CVELIST_MAX_ROWS]

    os.makedirs(os.path.dirname(CVE_CACHE_CSV), exist_ok=True)
    tmp_path = CVE_CACHE_CSV + ".tmp"
    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDNAMES)
        writer.writeheader()
        writer.writerows(capped)
    os.replace(tmp_path, CVE_CACHE_CSV)

    global _index
    _index = capped
    log.info("cve_dataset: cache rebuilt — %d rows from %d parsed CVE records", len(capped), len(rows))


async def refresh_if_stale() -> None:
    stale = True
    if os.path.exists(CVE_CACHE_CSV):
        age_hours = (time.time() - os.path.getmtime(CVE_CACHE_CSV)) / 3600
        stale = age_hours >= CVE_CSV_REFRESH_HOURS
    if not stale:
        return
    import asyncio
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _refresh_sync)
    except Exception as exc:
        log.warning("cve_dataset: refresh failed, keeping previous cache if any: %s", exc)


def load_index(force: bool = False) -> list[dict]:
    global _index
    if _index is not None and not force:
        return _index
    if not os.path.exists(CVE_CACHE_CSV):
        _index = []
        return _index
    with open(CVE_CACHE_CSV, newline="", encoding="utf-8") as f:
        _index = list(csv.DictReader(f))
    return _index


def _version_tuple(v: str) -> tuple[int, ...] | None:
    """Loose numeric-tuple parse — real-world banners (e.g. nmap/Shodan's
    "6.6.1p1 Ubuntu 2ubuntu2.13") aren't valid semver, so a strict parser
    (e.g. packaging.version) rejects most of them. Extracting the leading
    dotted-number run is a deliberately conservative compromise: good
    enough to compare "1.18.0" against "1.20.0", honest (returns None, not
    a guess) when there's nothing numeric to compare at all."""
    if not v:
        return None
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*)", v)
    if not m:
        return None
    return tuple(int(part) for part in m.group(1).split("."))


def _version_in_range(candidate: tuple[int, ...], start: str, end: str, end_type: str) -> bool | None:
    """True/False when both bounds are numerically comparable to the
    candidate; None when they aren't (e.g. a non-numeric version scheme) —
    callers must treat None as "can't verify", never as a match."""
    end_t = _version_tuple(end)
    if end_t is None:
        return None
    if end_type == "lessThan":
        if candidate >= end_t:
            return False
    else:  # lessThanOrEqual
        if candidate > end_t:
            return False
    start_t = _version_tuple(start) if start else None
    if start_t is not None and candidate < start_t:
        return False
    return True


def match(product: str, version: str | None = None, limit: int = 5) -> list[dict]:
    """Substring match on product/vendor against the local cache, then — when
    a version is given and the cached record has parseable version-range
    data — actually filter out candidates the given version is definitely
    NOT affected by, instead of only reordering by exact-string match.
    Ambiguous cases (non-numeric version schemes, missing range data) are
    kept but flagged via "version_verified", never silently dropped or
    silently presented as confirmed.

    Best-effort matching, not authoritative CPE resolution; good enough to
    surface candidates for EPSS/KEV enrichment."""
    index = load_index()
    if not index or not product:
        return []
    p = product.lower().strip()
    hits = [
        r for r in index
        if (r.get("product") and (r["product"].lower() in p or p in r["product"].lower()))
        or (r.get("vendor") and r["vendor"].lower() in p)
    ]

    candidate_tuple = _version_tuple(version) if version else None
    if candidate_tuple is not None:
        kept = []
        for r in hits:
            try:
                ranges = json.loads(r.get("version_ranges") or "[]")
            except (json.JSONDecodeError, TypeError):
                ranges = []
            if not ranges:
                r["version_verified"] = "no_range_data"
                kept.append(r)
                continue
            verdicts = [
                _version_in_range(candidate_tuple, rg.get("start", ""), rg.get("end", ""), rg.get("end_type", "lessThan"))
                for rg in ranges
            ]
            if any(v is True for v in verdicts):
                r["version_verified"] = "yes"
                kept.append(r)
            elif all(v is False for v in verdicts):
                continue  # definitely not affected — this is the actual fix
            else:
                r["version_verified"] = "unknown_scheme"
                kept.append(r)
        hits = kept
        hits.sort(key=lambda r: 0 if r.get("version_verified") == "yes" else 1)
    else:
        for r in hits:
            r["version_verified"] = "no_version_given"

    return hits[:limit]


def get_by_cve_id(cve_id: str) -> dict | None:
    """Exact CVE-ID lookup — for findings that already carry a trusted CVE ID
    from elsewhere (e.g. Shodan's own vuln list) and just need the real
    description text, without going through the fuzzy product/vendor
    substring match at all."""
    for r in load_index():
        if r.get("cve_id") == cve_id:
            return r
    return None


def cache_status() -> dict:
    if not os.path.exists(CVE_CACHE_CSV):
        return {"ready": False, "rows": 0, "age_hours": None}
    age_hours = round((time.time() - os.path.getmtime(CVE_CACHE_CSV)) / 3600, 1)
    return {"ready": True, "rows": len(load_index()), "age_hours": age_hours}

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
import logging
import os
import subprocess
import time
from datetime import datetime, timezone

from app.config import (
    CVE_CACHE_CSV, CVE_CACHE_REPO_DIR, CVE_CSV_REFRESH_HOURS,
    CVE_CSV_REMOTE_URL, CVE_CVELIST_MAX_ROWS, CVE_CVELIST_YEARS_BACK,
)

log = logging.getLogger("cve_dataset")

_index: list[dict] | None = None
_FIELDNAMES = ["cve_id", "vendor", "product", "version", "cvss_score", "published"]


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


def _extract_rows(path: str) -> list[dict]:
    import json
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

    if not affected:
        return [{"cve_id": cve_id, "vendor": "", "product": "", "version": "",
                  "cvss_score": cvss_score, "published": published}]

    rows = []
    for a in affected:
        vendor = str(a.get("vendor") or "").strip()
        product = str(a.get("product") or "").strip()
        if not product:
            continue
        version_str = ""
        for v in a.get("versions") or []:
            if v.get("status") == "affected":
                version_str = v.get("version") or v.get("lessThan") or ""
                break
        rows.append({"cve_id": cve_id, "vendor": vendor, "product": product,
                      "version": version_str, "cvss_score": cvss_score, "published": published})
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


def match(product: str, version: str | None = None, limit: int = 5) -> list[dict]:
    """Substring match on product/vendor against the local cache. Version,
    when given, only reorders results (exact-version hits first) — it does
    not filter, since most cached entries don't carry a full version range
    we can safely evaluate. Best-effort matching, not authoritative CPE
    resolution; good enough to surface candidates for EPSS/KEV enrichment."""
    index = load_index()
    if not index or not product:
        return []
    p = product.lower().strip()
    hits = [
        r for r in index
        if (r.get("product") and (r["product"].lower() in p or p in r["product"].lower()))
        or (r.get("vendor") and r["vendor"].lower() in p)
    ]
    if version:
        hits.sort(key=lambda r: 0 if r.get("version") == version else 1)
    return hits[:limit]


def cache_status() -> dict:
    if not os.path.exists(CVE_CACHE_CSV):
        return {"ready": False, "rows": 0, "age_hours": None}
    age_hours = round((time.time() - os.path.getmtime(CVE_CACHE_CSV)) / 3600, 1)
    return {"ready": True, "rows": len(load_index()), "age_hours": age_hours}

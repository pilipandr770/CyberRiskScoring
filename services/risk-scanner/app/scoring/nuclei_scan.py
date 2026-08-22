"""
Nuclei scan — detection-only tag set (see NUCLEI_TAGS in config.py). Used
against Tier 0 live hosts and, when available, Tier 1 office-IP hosts.
Non-destructive by construction: no rce/sqli/xss/ssrf/idor/auth-bypass tags,
only hygiene/misconfig/CVE-detection templates.
"""

from app.config import NUCLEI_RATE_LIMIT, NUCLEI_SEVERITIES, NUCLEI_TAGS, NUCLEI_TIMEOUT_SECONDS
from app.scoring import cve_enrich, tool_runner


def _severity_to_cvss(severity: str) -> float:
    return {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.5, "info": 1.0}.get(
        (severity or "").lower(), 4.0
    )


async def scan_urls(urls: list[str]) -> list[dict]:
    """Run nuclei against the given URLs/hosts. Returns findings shaped like
    every other source in the pipeline: {key, source, product, cve, cvss,
    epss, kev, category}. Returns [] if nuclei isn't available or times out
    — callers already treat an empty finding list as a valid (if less
    complete) result, same as every other best-effort source here."""
    if not urls or not tool_runner.is_available("nuclei"):
        return []

    try:
        stdout, _stderr, _rc = await tool_runner.run(
            [
                "nuclei", "-silent", "-jsonl",
                "-tags", NUCLEI_TAGS,
                "-severity", NUCLEI_SEVERITIES,
                "-rate-limit", str(NUCLEI_RATE_LIMIT),
                "-timeout", "10",
            ],
            timeout=NUCLEI_TIMEOUT_SECONDS,
            input_data="\n".join(urls),
        )
    except Exception:
        return []

    rows = tool_runner.parse_jsonlines(stdout)
    if not rows:
        return []

    # Pull out any CVE IDs nuclei's own template metadata already knows about.
    cve_ids_per_row = []
    all_cve_ids = set()
    for row in rows:
        info = row.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        cve_ids_per_row.append(cve_ids)
        all_cve_ids.update(cve_ids)

    enriched = await cve_enrich.enrich_cves(list(all_cve_ids)) if all_cve_ids else {}

    findings = []
    misconfig_groups: dict[tuple[str, str], dict] = {}
    for row, cve_ids in zip(rows, cve_ids_per_row):
        info = row.get("info", {}) or {}
        severity = info.get("severity", "info")
        template_id = row.get("template-id", "unknown-template")
        matched_at = row.get("matched-at") or row.get("host") or ""

        if cve_ids:
            for cve in cve_ids:
                enr = enriched.get(cve.upper(), {"epss": 0.0, "kev": False})
                findings.append({
                    "key": f"{matched_at}:{cve}",
                    "source": "nuclei",
                    "product": info.get("name", template_id),
                    "cve": cve,
                    "cvss": _severity_to_cvss(severity),
                    "epss": enr.get("epss", 0.0),
                    "kev": enr.get("kev", False),
                    "category": "internet_facing_data" if severity in ("high", "critical") else "internet_facing_generic",
                })
        else:
            # Hygiene/misconfig templates (missing headers, exposed panel,
            # weak TLS, ...) commonly fire once per probed subdomain — group
            # by template so "missing security headers" on 10 subdomains
            # renders as one line, not 10 near-identical bullets.
            key = (template_id, severity)
            group = misconfig_groups.setdefault(key, {"name": info.get("name", template_id), "hosts": set()})
            group["hosts"].add(matched_at)

    for (template_id, severity), group in misconfig_groups.items():
        n_hosts = len(group["hosts"])
        name = group["name"] + (f" ({n_hosts} hosts affected)" if n_hosts > 1 else "")
        findings.append({
            "key": f"{template_id}:{n_hosts}-hosts",
            "source": "nuclei",
            "product": name,
            "cve": None,
            "cvss": _severity_to_cvss(severity),
            "epss": 0.0,
            "kev": False,
            "category": "misconfig",
        })

    return findings

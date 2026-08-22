"""
Shodan lookups — Tier 1 (office IP/range provided).

Shodan never touches the target directly; it serves data it already
collected from its own internet-wide scanning. That makes it strictly
safer than the active fingerprinting phase, and it's the main source for
IoT/OT/POS exposure (cameras, NVRs, till systems) that domain-only OSINT
can't see at all.
"""

import httpx

from app.config import SHODAN_API_KEY, IOT_OT_KEYWORDS

_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


def is_iot_ot_product(product: str) -> bool:
    p = (product or "").lower()
    return any(kw in p for kw in IOT_OT_KEYWORDS)


async def lookup_host(ip: str) -> dict:
    """
    Return {"ip": ..., "services": [{"port", "product", "version", "cves": [...]}], "error": None}
    Each service's "cves" list comes straight from Shodan's own vuln matching
    where present (fast path — no separate CPE lookup needed for those).
    """
    if not SHODAN_API_KEY:
        return {"ip": ip, "services": [], "error": "SHODAN_API_KEY not configured — Tier 1 skipped"}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(_HOST_URL.format(ip=ip), params={"key": SHODAN_API_KEY})
            if resp.status_code == 404:
                return {"ip": ip, "services": [], "error": "no Shodan data for this host"}
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return {"ip": ip, "services": [], "error": f"Shodan lookup failed: {exc}"}

    # Shodan can return several historical scan snapshots for the same open
    # port (common on heavily-rescanned research hosts) — dedupe by port so
    # one real service doesn't turn into N separate findings-generating
    # "services", each independently capped at the CVE-match limit.
    services_by_port: dict[int, dict] = {}
    for item in data.get("data", []):
        port = item.get("port")
        product = item.get("product", "") or ""
        version = item.get("version", "") or ""
        # Keep Shodan's own per-CVE cvss score when it hands us one, instead
        # of discarding it — needed to rank, not just list, the CVEs below.
        vulns_raw = item.get("vulns", {})
        vulns: dict[str, float | None] = {}
        if isinstance(vulns_raw, dict):
            for cve_id, info in vulns_raw.items():
                score = info.get("cvss") if isinstance(info, dict) else None
                vulns[cve_id] = score
        # product field only — matching the raw banner text too easily
        # false-positives (e.g. an unrelated copyright line containing one
        # of the keywords), and misclassification skews the risk category.
        is_iot = is_iot_ot_product(product)

        existing = services_by_port.get(port)
        if existing is None:
            services_by_port[port] = {
                "port": port,
                "transport": item.get("transport", "tcp"),
                "product": product,
                "version": version,
                "cves": vulns,
                "is_iot_ot": is_iot,
            }
        else:
            existing["cves"].update(vulns)
            existing["is_iot_ot"] = existing["is_iot_ot"] or is_iot
            existing["product"] = existing["product"] or product
            existing["version"] = existing["version"] or version

    # A single old, heavily-rescanned service (e.g. this project's own test
    # target, scanme.nmap.org, running an 11-year-old Apache) can legitimately
    # have 100+ applicable CVEs in Shodan's history. Dumping all of them into
    # the report is noise, not signal — keep only the most severe handful per
    # service; the risk-multiplier formula already caps per-category at top-5
    # internally, but the *displayed* finding list needs the same discipline.
    _MAX_CVES_PER_SERVICE = 5
    services = []
    for svc in services_by_port.values():
        ranked = sorted(svc["cves"].items(), key=lambda kv: (kv[1] or 0), reverse=True)
        svc["cves"] = [cve_id for cve_id, _score in ranked[:_MAX_CVES_PER_SERVICE]]
        svc["cve_scores"] = dict(ranked[:_MAX_CVES_PER_SERVICE])
        services.append(svc)

    return {"ip": ip, "services": services, "error": None}


async def lookup_range(cidr_or_ip_list: str) -> list[dict]:
    """
    Accepts a single IP, a comma-separated list, or a small CIDR already
    expanded by the caller. Kept simple on purpose — no Shodan paid
    net-block search here, MVP works host-by-host.
    """
    ips = [ip.strip() for ip in cidr_or_ip_list.split(",") if ip.strip()]
    results = []
    for ip in ips:
        results.append(await lookup_host(ip))
    return results

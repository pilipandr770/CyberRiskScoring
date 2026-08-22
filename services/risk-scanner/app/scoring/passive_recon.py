"""
Tier 0 recon: subfinder -> dnsx -> httpx, using the real ProjectDiscovery
binaries baked into the image. Falls back to the pure-Python crt.sh +
manual HTTP probe (the original MVP path) if the binaries aren't present
for any reason — same graceful-degradation pattern used for the CVE cache
and Shodan.
"""

import json

import httpx as httpx_client

from app.scoring import tool_runner

_MAX_HOSTS_PROBED = 15


async def _crt_sh_subdomains(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx_client.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        return []
    names = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and domain in name:
                names.add(name)
    return sorted(names)


async def _subfinder(domain: str) -> list[str]:
    if not tool_runner.is_available("subfinder"):
        return await _crt_sh_subdomains(domain)
    try:
        stdout, _stderr, _rc = await tool_runner.run(
            ["subfinder", "-d", domain, "-silent", "-json"], timeout=60
        )
    except Exception:
        return await _crt_sh_subdomains(domain)

    subs = set()
    for row in tool_runner.parse_jsonlines(stdout):
        host = row.get("host")
        if host:
            subs.add(host.lower())
    return sorted(subs) or await _crt_sh_subdomains(domain)


async def _dnsx_filter_live(hosts: list[str]) -> list[str]:
    if not hosts or not tool_runner.is_available("dnsx"):
        return hosts
    try:
        stdout, _stderr, _rc = await tool_runner.run(
            ["dnsx", "-silent", "-json"], timeout=60, input_data="\n".join(hosts)
        )
    except Exception:
        return hosts
    live = [row["host"] for row in tool_runner.parse_jsonlines(stdout) if row.get("host")]
    return live or hosts


async def _httpx_probe(hosts: list[str]) -> list[dict]:
    """Batch probe via the real httpx binary — status, server header,
    tech-detect. Falls back to a manual per-host GET if httpx isn't
    available."""
    if not hosts:
        return []

    if tool_runner.is_available("httpx"):
        try:
            stdout, _stderr, _rc = await tool_runner.run(
                ["httpx", "-silent", "-json", "-tech-detect", "-status-code",
                 "-follow-redirects", "-include-response-header", "-timeout", "10"],
                timeout=90, input_data="\n".join(hosts),
            )
            rows = tool_runner.parse_jsonlines(stdout)
            if rows:
                probes = []
                for row in rows:
                    url = row.get("url", "")
                    probes.append({
                        "host": row.get("input") or row.get("host"),
                        "reachable": True,
                        "https": url.startswith("https"),
                        "status_code": row.get("status_code"),
                        "server": row.get("webserver"),
                        "tech_hints": row.get("tech", []),
                        # httpx normalizes header names to snake_case in its
                        # JSON output (e.g. "strict_transport_security"), not
                        # the hyphenated wire form — matching on the hyphenated
                        # string here always missed a real HSTS header.
                        "has_hsts": "strict_transport_security" in {
                            h.lower() for h in (row.get("header", {}) or {}).keys()
                        } if isinstance(row.get("header"), dict) else False,
                        "error": None,
                    })
                return probes
        except Exception:
            pass

    return [await _manual_probe(h) for h in hosts]


async def _manual_probe(host: str) -> dict:
    result = {"host": host, "reachable": False, "https": False, "server": None,
              "tech_hints": [], "has_hsts": False, "error": None}
    for scheme in ("https", "http"):
        try:
            async with httpx_client.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"{scheme}://{host}")
            result["reachable"] = True
            result["https"] = scheme == "https"
            result["status_code"] = resp.status_code
            server = resp.headers.get("server")
            if server:
                result["server"] = server
                result["tech_hints"].append(server)
            result["has_hsts"] = "strict-transport-security" in {k.lower() for k in resp.headers.keys()}
            break
        except Exception as exc:
            result["error"] = str(exc)
            continue
    return result


async def run_tier0(domain: str) -> dict:
    subdomains = await _subfinder(domain)
    hosts = list(dict.fromkeys([domain] + [s for s in subdomains if s != domain]))
    hosts = await _dnsx_filter_live(hosts)
    hosts_to_probe = hosts[:_MAX_HOSTS_PROBED]

    probes = await _httpx_probe(hosts_to_probe)

    return {
        "domain": domain,
        "subdomains_found": len(subdomains),
        "subdomains_sample": subdomains[:20],
        "probes": probes,
        "live_hosts": hosts_to_probe,
    }

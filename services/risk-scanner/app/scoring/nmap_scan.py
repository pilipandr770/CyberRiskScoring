"""
Light nmap version-detection for Tier 1 (office IP provided) — a
non-destructive supplement to Shodan's data, which can be stale or
incomplete for a given host. Version banner grab only (-sV), no scripts,
no exploitation.
"""

import xml.etree.ElementTree as ET

from app.scoring import tool_runner

_COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,993,995,3389,5900,8080,8443,8888,9000"


async def scan_host(ip: str) -> dict:
    if not tool_runner.is_available("nmap"):
        return {"ip": ip, "services": [], "error": "nmap not available"}

    try:
        stdout, _stderr, _rc = await tool_runner.run(
            ["nmap", "-sV", "-Pn", "-p", _COMMON_PORTS, "-oX", "-", ip],
            timeout=180,
        )
    except Exception as exc:
        return {"ip": ip, "services": [], "error": f"nmap failed: {exc}"}

    services = []
    try:
        root = ET.fromstring(stdout)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                product = (svc.get("product") if svc is not None else "") or ""
                version = (svc.get("version") if svc is not None else "") or ""
                services.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "product": product,
                    "version": version,
                    "service_name": (svc.get("name") if svc is not None else "") or "",
                })
    except ET.ParseError:
        return {"ip": ip, "services": [], "error": "could not parse nmap output"}

    return {"ip": ip, "services": services, "error": None}


async def scan_range(cidr_or_ip_list: str) -> list[dict]:
    ips = [ip.strip() for ip in cidr_or_ip_list.split(",") if ip.strip()]
    return [await scan_host(ip) for ip in ips]

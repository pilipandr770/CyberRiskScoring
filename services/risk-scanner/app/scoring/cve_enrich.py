"""
CVE enrichment — EPSS + CISA KEV.

Ported from BB_Assist (backend/services/cve_enricher.py). Same public APIs,
same caching approach — this part of the bug-bounty pipeline needed no
adaptation for the insurance use case, only the caller changes.
"""

import asyncio
import re
import time

import httpx

_kev_cache: set[str] = set()
_kev_fetched_at: float = 0.0
_KEV_TTL = 3600
_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_TTL = 21600
_epss_cache: dict[str, dict] = {}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    return list({m.upper() for m in _CVE_RE.findall(text or "")})


async def _refresh_kev_if_stale() -> None:
    global _kev_cache, _kev_fetched_at
    now = time.monotonic()
    if now - _kev_fetched_at < _KEV_TTL:
        return
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        _kev_cache = {v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
        _kev_fetched_at = now
    except Exception:
        pass  # KEV enrichment is optional — don't fail the scan over it


async def is_in_kev(cve_id: str) -> bool:
    await _refresh_kev_if_stale()
    return cve_id.upper() in _kev_cache


async def get_epss(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    now = time.monotonic()
    result: dict[str, dict] = {}
    to_fetch: list[str] = []
    for cve in cve_ids:
        cached = _epss_cache.get(cve.upper())
        if cached and (now - cached.get("ts", 0)) < _EPSS_TTL:
            result[cve.upper()] = cached
        else:
            to_fetch.append(cve.upper())

    if to_fetch:
        for batch_start in range(0, len(to_fetch), 100):
            batch = to_fetch[batch_start:batch_start + 100]
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(_EPSS_URL, params={"cve": ",".join(batch)})
                    resp.raise_for_status()
                    data = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "").upper()
                    entry = {
                        "score": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                        "ts": now,
                    }
                    _epss_cache[cve_id] = entry
                    result[cve_id] = entry
            except Exception:
                continue

    return result


async def enrich_cves(cve_ids: list[str]) -> dict[str, dict]:
    """
    Return {cve_id: {"epss": float, "epss_percentile": float, "kev": bool}}
    for every CVE ID passed in. Missing lookups default to epss=0.0, kev=False
    rather than dropping the CVE — an unscored CVE still counts, just at floor.
    """
    if not cve_ids:
        return {}
    epss_data, kev_flags = await asyncio.gather(
        get_epss(cve_ids),
        asyncio.gather(*[is_in_kev(c) for c in cve_ids]),
    )
    kev_map = dict(zip(cve_ids, kev_flags))
    return {
        cve: {
            "epss": epss_data.get(cve, {}).get("score", 0.0),
            "epss_percentile": epss_data.get(cve, {}).get("percentile", 0.0),
            "kev": kev_map.get(cve, False),
        }
        for cve in cve_ids
    }

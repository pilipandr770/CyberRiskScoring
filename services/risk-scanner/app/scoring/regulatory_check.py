"""
Formal-requirements checker — Impressum completeness (§5 TMG/DDG) and
cookie-consent-banner presence vs. pre-consent tracking (§25 TTDSG).

This is heuristic pattern-matching against the live page, not a legal
review — every result carries that caveat and should be labeled as such
anywhere it's shown. It exists to feed a real, non-hardcoded value into
the DSK fine calculation's "formal violation" ground (Art. 83(4) DSGVO) —
until now that was always False. It deliberately does NOT feed the
technical risk-multiplier/raw_score: missing paperwork doesn't raise
breach probability, so it stays out of that calculation and only drives
the separate formal-fine figure.
"""

import re
from urllib.parse import urljoin

import httpx

_IMPRESSUM_LINK_RE = re.compile(r'href=["\']([^"\']*impressum[^"\']*)["\']', re.IGNORECASE)
_ADDRESS_HINT_RE = re.compile(r"\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß]+")  # PLZ + Ort pattern
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_GESCHAEFTSFUEHRER_RE = re.compile(r"Geschäftsführer|Vertretungsberechtigt|Inhaber", re.IGNORECASE)
_HRB_RE = re.compile(r"HRB\s*\d+|Handelsregister", re.IGNORECASE)

_TRACKING_COOKIE_PREFIXES = ("_ga", "_gid", "_fbp", "_gcl", "_hjid", "ajs_")
_CMP_SCRIPT_HINTS = (
    "cookiebot", "onetrust", "usercentrics", "borlabs", "cookieyes",
    "iubenda", "consentmanager", "cmpbox", "klaro", "cookiefirst",
)
_TRACKING_SCRIPT_HINTS = (
    "googletagmanager.com/gtag", "google-analytics.com",
    "connect.facebook.net", "facebook.net/en_us/fbevents",
)

_HEURISTIC_NOTE = "Heuristische Mustererkennung — keine Rechtsberatung, keine vollständige TMG/DDG/TTDSG-Prüfung"


async def _fetch(url: str) -> httpx.Response | None:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            return await client.get(url)
    except Exception:
        return None


async def check_impressum(base_url: str, html: str) -> dict:
    match = _IMPRESSUM_LINK_RE.search(html)
    if not match:
        return {"found": False, "complete": False, "missing": ["Impressum-Link nicht gefunden"], "note": _HEURISTIC_NOTE}

    link = match.group(1)
    if not link.startswith("http"):
        link = urljoin(base_url, link)

    resp = await _fetch(link)
    if resp is None:
        return {"found": True, "complete": False, "missing": ["Impressum-Seite nicht erreichbar"], "note": _HEURISTIC_NOTE}

    page = resp.text
    missing = []
    if not _ADDRESS_HINT_RE.search(page):
        missing.append("Anschrift (PLZ/Ort) nicht erkannt")
    if not _EMAIL_RE.search(page):
        missing.append("E-Mail-Adresse nicht erkannt")
    if not _GESCHAEFTSFUEHRER_RE.search(page):
        missing.append("Vertretungsberechtigte Person nicht erkannt")

    return {"found": True, "complete": not missing, "missing": missing, "note": _HEURISTIC_NOTE}


async def check_cookie_consent(base_url: str) -> dict:
    """Fresh (no prior cookies) fetch of the homepage: does the raw
    response already Set-Cookie a known tracking cookie before any consent
    interaction could have happened, and does a recognizable consent-
    management-platform script appear."""
    resp = await _fetch(base_url)
    if resp is None:
        return {"checked": False, "note": "Homepage nicht erreichbar"}

    html = resp.text.lower()
    try:
        set_cookie_headers = resp.headers.get_list("set-cookie")
    except AttributeError:
        raw = resp.headers.get("set-cookie")
        set_cookie_headers = [raw] if raw else []

    cookie_names = [h.split("=", 1)[0].strip() for h in set_cookie_headers if h]
    pre_consent_tracking = [c for c in cookie_names if any(c.startswith(p) for p in _TRACKING_COOKIE_PREFIXES)]
    has_cmp = any(hint in html for hint in _CMP_SCRIPT_HINTS)
    has_tracking_script = any(hint in html for hint in _TRACKING_SCRIPT_HINTS)

    violation = bool(pre_consent_tracking) or (has_tracking_script and not has_cmp)

    return {
        "checked": True,
        "violation": violation,
        "pre_consent_tracking_cookies": pre_consent_tracking,
        "has_cmp_detected": has_cmp,
        "has_tracking_script": has_tracking_script,
        "note": _HEURISTIC_NOTE,
    }


async def check_formal_requirements(domain: str) -> dict:
    """Entry point — tries https then http, same fallback pattern as the
    rest of the recon layer. Returns has_violation=True if either check
    finds a problem, plus the sub-results for report transparency."""
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}"
        resp = await _fetch(base_url)
        if resp is not None:
            break
    else:
        return {
            "impressum": {"found": False, "complete": False, "missing": ["Homepage nicht erreichbar"], "note": _HEURISTIC_NOTE},
            "cookie_consent": {"checked": False},
            "has_violation": False,
        }

    impressum = await check_impressum(base_url, resp.text)
    cookie_consent = await check_cookie_consent(base_url)
    has_violation = (not impressum.get("complete", False)) or bool(cookie_consent.get("violation"))

    return {"impressum": impressum, "cookie_consent": cookie_consent, "has_violation": has_violation}

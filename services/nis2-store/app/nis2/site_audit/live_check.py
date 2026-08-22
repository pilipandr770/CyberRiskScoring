"""
NIS2 Site Audit — Live Security Check
======================================
Pure-Python web-security scanner:
  • HTTP security headers (CSP, X-Frame-Options, HSTS, etc.)
  • TLS/SSL certificate info
  • Cookie security flags
  • DNS: SPF, DMARC, DKIM, DNSSEC

No external binaries required — works on Render.com without Docker.

Originally developed for NIS2-SDWGO (https://github.com/pilipandr770/NIS2-SDWGO).
Adapted for vat-verifizierung.de NIS2 Compliance Platform.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# SSRF protection — reject private/loopback/link-local targets
# ---------------------------------------------------------------------------
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_public_target(target: str) -> bool:
    """Return True only if target resolves to a public IP address."""
    try:
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
        for _family, _type, _proto, _cname, sockaddr in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if any(ip in net for net in _PRIVATE_RANGES):
                return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helper: run subprocess with timeout
# ---------------------------------------------------------------------------
def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# ---------------------------------------------------------------------------
# HTTP headers + TLS check
# ---------------------------------------------------------------------------
_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "x-permitted-cross-domain-policies",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]


def _check_http(target: str) -> Dict[str, Any]:
    """Fetch HTTP headers and return analysis."""
    result: Dict[str, Any] = {
        "url": target,
        "status_code": None,
        "headers": {},
        "missing_headers": [],
        "present_headers": [],
        "warnings": [],
        "tls_valid": None,
        "tls_expiry": None,
        "tls_issuer": None,
        "tls_subject": None,
        "hsts_present": False,
        "hsts_max_age": None,
        "csp_strength": "none",
    }

    try:
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "NIS2-SecurityAudit/1.0"},
            method="GET",
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            result["status_code"] = resp.status
            raw_headers: Dict[str, str] = dict(resp.headers)
            result["headers"] = {k.lower(): v for k, v in raw_headers.items()}
    except ssl.SSLCertVerificationError as exc:
        result["tls_valid"] = False
        result["warnings"].append(f"TLS-Zertifikatsfehler: {exc}")
    except urllib.error.HTTPError as exc:
        result["status_code"] = exc.code
        raw_headers = dict(exc.headers)
        result["headers"] = {k.lower(): v for k, v in raw_headers.items()}
    except Exception as exc:
        result["warnings"].append(f"Verbindungsfehler: {exc}")

    headers = result["headers"]

    # Security header presence
    for h in _SECURITY_HEADERS:
        if h in headers:
            result["present_headers"].append(h)
        else:
            result["missing_headers"].append(h)

    # HSTS analysis
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        result["hsts_present"] = True
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    result["hsts_max_age"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if result["hsts_max_age"] and result["hsts_max_age"] < 15552000:
            result["warnings"].append(
                f"HSTS max-age zu kurz: {result['hsts_max_age']}s (empfohlen ≥ 15552000)"
            )

    # CSP strength
    csp = headers.get("content-security-policy", "")
    if csp:
        if "default-src 'none'" in csp or "default-src 'self'" in csp:
            result["csp_strength"] = "strong"
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            result["csp_strength"] = "weak"
            result["warnings"].append("CSP enthält 'unsafe-inline' oder 'unsafe-eval'")
        else:
            result["csp_strength"] = "medium"

    # X-Frame-Options
    xfo = headers.get("x-frame-options", "").upper()
    if xfo and xfo not in ("DENY", "SAMEORIGIN"):
        result["warnings"].append(f"X-Frame-Options hat ungewöhnlichen Wert: {xfo}")

    return result


# ---------------------------------------------------------------------------
# TLS certificate info
# ---------------------------------------------------------------------------
def _check_tls(hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": None,
        "expiry": None,
        "issuer": None,
        "subject": None,
        "days_remaining": None,
        "warnings": [],
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True

                # Subject
                subj = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subj.get("commonName", "")

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", issuer.get("commonName", ""))

                # Expiry
                exp_str = cert.get("notAfter", "")
                if exp_str:
                    exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    result["expiry"] = exp_dt.strftime("%Y-%m-%d")
                    days = (exp_dt - datetime.now(UTC)).days
                    result["days_remaining"] = days
                    if days < 30:
                        result["warnings"].append(
                            f"Zertifikat läuft in {days} Tag(en) ab!"
                        )
    except ssl.SSLCertVerificationError as exc:
        # Connected successfully but certificate is genuinely invalid
        result["valid"] = False
        result["warnings"].append(f"SSL-Zertifikat ungültig: {exc}")
    except ssl.SSLError as exc:
        result["valid"] = False
        result["warnings"].append(f"SSL-Fehler: {exc}")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        # Could not reach the host — cannot determine cert validity
        # (common when scanning own domain behind Cloudflare proxy)
        result["valid"] = None
        result["warnings"].append(f"TLS-Verbindung nicht erreichbar: {exc}")
    except Exception as exc:
        result["valid"] = None
        result["warnings"].append(f"TLS-Check nicht durchführbar: {exc}")
    return result


# ---------------------------------------------------------------------------
# Cookie security flags
# ---------------------------------------------------------------------------
def _check_cookies(target: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "cookies": [],
        "warnings": [],
        "insecure_cookies": [],
    }
    try:
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "NIS2-SecurityAudit/1.0"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            # Collect Set-Cookie headers
            for key, val in resp.headers.items():
                if key.lower() != "set-cookie":
                    continue
                cookie_str = val
                name = cookie_str.split("=")[0].strip()
                flags_lower = cookie_str.lower()

                cookie_info = {
                    "name": name,
                    "raw": cookie_str,
                    "httponly": "httponly" in flags_lower,
                    "secure": "secure" in flags_lower,
                    "samesite": "samesite" in flags_lower,
                }
                result["cookies"].append(cookie_info)

                warnings: List[str] = []
                if not cookie_info["httponly"]:
                    warnings.append("fehlendes HttpOnly-Flag")
                if not cookie_info["secure"]:
                    warnings.append("fehlendes Secure-Flag")
                if not cookie_info["samesite"]:
                    warnings.append("fehlendes SameSite-Flag")

                if warnings:
                    result["insecure_cookies"].append(
                        f"{name}: {', '.join(warnings)}"
                    )
                    result["warnings"].extend(
                        f"Cookie '{name}': {w}" for w in warnings
                    )
    except Exception as exc:
        result["warnings"].append(f"Cookie-Check fehlgeschlagen: {exc}")
    return result


# ---------------------------------------------------------------------------
# DNS audit (SPF, DMARC, DKIM, DNSSEC)
# ---------------------------------------------------------------------------
def _dns_txt_records(domain: str, record_type: str = "TXT") -> List[str]:
    """Fetch DNS TXT/records using 'dig' if available, else empty list."""
    out = _run(["dig", "+short", f"{domain}", record_type])
    if not out.strip():
        return []
    return [line.strip().strip('"') for line in out.strip().splitlines() if line.strip()]


def _check_dns(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "spf": None,
        "spf_raw": None,
        "dmarc": None,
        "dmarc_raw": None,
        "dkim_checked": False,
        "dnssec": False,
        "warnings": [],
        "records": {},
    }

    # SPF
    spf_records = [r for r in _dns_txt_records(domain) if r.startswith("v=spf1")]
    if spf_records:
        result["spf"] = "present"
        result["spf_raw"] = spf_records[0]
        if "+all" in spf_records[0]:
            result["warnings"].append("SPF enthält '+all' — erlaubt alle Absender (sehr unsicher)")
        elif "~all" in spf_records[0]:
            result["warnings"].append("SPF enthält '~all' (SoftFail) — schwache Konfiguration")
    else:
        result["spf"] = "missing"
        result["warnings"].append("Kein SPF-Record gefunden (Spoofing-Risiko)")

    # DMARC
    dmarc_records = _dns_txt_records(f"_dmarc.{domain}")
    dmarc_txts = [r for r in dmarc_records if r.startswith("v=DMARC1")]
    if dmarc_txts:
        result["dmarc"] = "present"
        result["dmarc_raw"] = dmarc_txts[0]
        if "p=none" in dmarc_txts[0]:
            result["warnings"].append(
                "DMARC-Policy ist 'none' — keine Schutzwirkung (empfohlen: quarantine/reject)"
            )
    else:
        result["dmarc"] = "missing"
        result["warnings"].append("Kein DMARC-Record gefunden")

    # DNSSEC (check DS record)
    ds_records = _dns_txt_records(domain, "DS")
    if ds_records:
        result["dnssec"] = True
    else:
        result["warnings"].append("DNSSEC nicht aktiviert oder keine DS-Records gefunden")

    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run_basic_checks(domain: str) -> Dict[str, Any]:
    """
    Adapter used by the continuous monitoring scanner.
    Calls fetch_live_check and converts the result into the format the scanner expects:
      { 'overall_score': float, 'checks': { name: { 'status', 'issues': [...] } } }
    """
    target = domain if domain.startswith(("http://", "https://")) else f"https://{domain}"
    raw = fetch_live_check(target)

    if "error" in raw:
        return {"overall_score": 0.0, "checks": {}, "error": raw["error"]}

    checks: Dict[str, Any] = {}
    score = 100.0

    # ── TLS ──────────────────────────────────────────────────────
    tls = raw.get("tls", {})
    tls_issues = []
    if tls.get("valid") is False:
        score -= 30
        tls_issues.append({
            "severity": "critical",
            "title": "TLS-Zertifikat ungültig",
            "description": "Das TLS-Zertifikat des Servers ist ungültig oder konnte nicht validiert werden.",
            "recommendation": "Zertifikat erneuern (z. B. Let's Encrypt). HTTPS muss korrekt konfiguriert sein (§30 Abs. 2 Nr. 4 BSIG).",
        })
    days = tls.get("days_remaining")
    if days is not None and days < 30:
        score -= 20
        tls_issues.append({
            "severity": "high",
            "title": f"Zertifikat läuft in {days} Tag(en) ab",
            "description": f"Das TLS-Zertifikat ist nur noch {days} Tag(e) gültig.",
            "recommendation": "Zertifikat vor Ablauf erneuern, um Verbindungsausfälle zu vermeiden.",
        })
    tls_unreachable = tls.get("valid") is None
    checks["tls"] = {
        "status": "PASSED" if not tls_issues else ("WARNING" if tls_unreachable else "FAILED"),
        "issues": tls_issues,
    }

    # ── HTTP security headers ─────────────────────────────────────
    http = raw.get("http", {})
    missing = http.get("missing_headers", [])
    header_issues = []
    header_weights = {
        "content-security-policy": ("high", 10),
        "strict-transport-security": ("high", 10),
        "x-frame-options": ("medium", 5),
        "x-content-type-options": ("medium", 5),
        "referrer-policy": ("low", 3),
        "permissions-policy": ("low", 3),
        "cross-origin-opener-policy": ("low", 2),
        "cross-origin-embedder-policy": ("low", 2),
    }
    _header_rec = {
        "content-security-policy": "Content-Security-Policy implementieren, um XSS-Angriffe zu verhindern (z. B. default-src 'self').",
        "strict-transport-security": "HSTS aktivieren: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        "x-frame-options": "X-Frame-Options: DENY oder SAMEORIGIN setzen, um Clickjacking zu verhindern.",
        "x-content-type-options": "X-Content-Type-Options: nosniff setzen, um MIME-Sniffing zu verhindern.",
        "referrer-policy": "Referrer-Policy: strict-origin-when-cross-origin setzen.",
        "permissions-policy": "Permissions-Policy Header hinzufügen, um Browser-Features zu beschränken.",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy: same-origin setzen.",
        "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy: require-corp setzen.",
    }
    for h in missing:
        sev, penalty = header_weights.get(h, ("low", 2))
        score -= penalty
        header_issues.append({
            "severity": sev,
            "title": f"Fehlender Header: {h}",
            "description": f"Der Security-Header '{h}' ist nicht gesetzt.",
            "recommendation": _header_rec.get(h, f"Header '{h}' zum HTTP-Response hinzufügen."),
        })
    # CSP weak
    if http.get("csp_strength") == "weak":
        score -= 5
        header_issues.append({
            "severity": "medium",
            "title": "Schwache Content-Security-Policy (unsafe-inline / unsafe-eval)",
            "description": "Die CSP enthält 'unsafe-inline' oder 'unsafe-eval', was XSS-Angriffe ermöglicht.",
            "recommendation": "unsafe-inline und unsafe-eval aus der CSP entfernen. Nonces oder Hashes verwenden.",
        })
    checks["http_headers"] = {
        "status": "PASSED" if not header_issues else ("FAILED" if any(i["severity"] in ("critical", "high") for i in header_issues) else "WARNING"),
        "issues": header_issues,
    }

    # ── Cookies ───────────────────────────────────────────────────
    cookies = raw.get("cookies", {})
    cookie_issues = []
    for msg in cookies.get("insecure_cookies", []):
        score -= 5
        cookie_issues.append({
            "severity": "medium",
            "title": f"Unsicheres Cookie: {msg.split(':')[0]}",
            "description": msg,
            "recommendation": "HttpOnly, Secure und SameSite=Strict Flags für alle Session-Cookies setzen.",
        })
    checks["cookies"] = {
        "status": "PASSED" if not cookie_issues else "WARNING",
        "issues": cookie_issues,
    }

    # ── DNS ───────────────────────────────────────────────────────
    dns = raw.get("dns", {})
    dns_issues = []
    if dns.get("spf") == "missing":
        score -= 10
        dns_issues.append({
            "severity": "high",
            "title": "SPF-Record fehlt",
            "description": "Kein SPF-DNS-Eintrag gefunden. E-Mail-Spoofing ist möglich.",
            "recommendation": "SPF-TXT-Record in DNS hinzufügen: 'v=spf1 include:<mail-provider> -all'",
        })
    if dns.get("dmarc") == "missing":
        score -= 10
        dns_issues.append({
            "severity": "high",
            "title": "DMARC-Record fehlt",
            "description": "Kein DMARC-Eintrag gefunden. E-Mail-Spoofing ist ohne Schutz möglich.",
            "recommendation": "DMARC-TXT-Record unter _dmarc.<domain> hinzufügen: 'v=DMARC1; p=quarantine; rua=mailto:...'",
        })
    if not dns.get("dnssec"):
        score -= 5
        dns_issues.append({
            "severity": "low",
            "title": "DNSSEC nicht aktiviert",
            "description": "DNSSEC ist nicht aktiviert. DNS-Hijacking-Angriffe sind möglich.",
            "recommendation": "DNSSEC beim Domain-Registrar aktivieren.",
        })
    checks["dns"] = {
        "status": "PASSED" if not dns_issues else ("FAILED" if any(i["severity"] == "high" for i in dns_issues) else "WARNING"),
        "issues": dns_issues,
    }

    return {
        "overall_score": max(0.0, min(100.0, round(score, 1))),
        "checks": checks,
        "raw": raw,
    }


def fetch_live_check(target: str) -> Dict[str, Any]:
    """
    Run all Python-native security checks against *target* (URL or domain).

    Returns a dict with keys: http, tls, cookies, dns, warnings, target.
    """
    # Normalise target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    target = target.rstrip("/")

    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]

    if not is_public_target(target):
        return {
            "error": "SSRF-Schutz: Ziel ist keine öffentlich erreichbare Adresse.",
            "target": target,
        }

    http_result = _check_http(target)
    tls_result = _check_tls(hostname)
    cookie_result = _check_cookies(target)
    dns_result = _check_dns(hostname)

    all_warnings = (
        http_result.get("warnings", [])
        + tls_result.get("warnings", [])
        + cookie_result.get("warnings", [])
        + dns_result.get("warnings", [])
    )

    return {
        "target": target,
        "hostname": hostname,
        "checked_at": datetime.now(UTC).isoformat(),
        "http": http_result,
        "tls": tls_result,
        "cookies": cookie_result,
        "dns": dns_result,
        "warnings": all_warnings,
        "warning_count": len(all_warnings),
    }

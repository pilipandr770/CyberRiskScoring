"""
Translates our internal finding shape into the exact shape nis2.store's
existing `microservice_client.py` already expects from the old external
pentesting microservice: title, description, severity, severity_rank,
cvss, dsgvo_article, recommendation, tool. Matching their contract means
their compliance_report/incident_response/dashboard code needs zero
changes — only the URL they call changes.
"""

_SEVERITY_RANK = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

# Best-effort DSGVO article mapping per finding category — informative for
# their compliance_report display, not an authoritative legal classification.
_CATEGORY_TO_ARTICLE = {
    "iot_ot_cve": "Art. 32 (Sicherheit der Verarbeitung)",
    "iot_ot_panel": "Art. 32 (Sicherheit der Verarbeitung)",
    "internet_facing_data": "Art. 32 (Sicherheit der Verarbeitung)",
    "internet_facing_generic": "Art. 32 (Sicherheit der Verarbeitung)",
    "misconfig": "Art. 32 (Sicherheit der Verarbeitung)",
    "internal_passive": "Art. 32 (Sicherheit der Verarbeitung)",
}


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _fallback_recommendation(f: dict) -> str:
    product = f.get("product") or "the affected system"
    if f.get("cve"):
        return f"Update {product} to the latest vendor-supported version."
    if f.get("category") == "misconfig":
        return f"Review and harden the configuration of {product}."
    return f"Review {product} with your IT provider."


def to_microservice_findings(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        severity = _severity_from_cvss(f.get("cvss") or 0)
        title = f.get("cve") or f.get("product") or "Finding"
        out.append({
            "title": f"{f.get('product', 'Unknown')} — {title}",
            "description": f"Category: {f.get('category')}, source: {f.get('source')}.",
            "severity": severity,
            "severity_rank": _SEVERITY_RANK[severity],
            "cvss": f.get("cvss"),
            "dsgvo_article": _CATEGORY_TO_ARTICLE.get(f.get("category"), "Art. 32 (Sicherheit der Verarbeitung)"),
            "recommendation": _fallback_recommendation(f),
            "tool": f.get("source", "risk-scanner"),
        })
    return out

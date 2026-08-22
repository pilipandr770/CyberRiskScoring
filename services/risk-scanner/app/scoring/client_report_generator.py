"""
Client-facing report — a distinct document from the agent/underwriter
report, not a relabeled version of it. Different audience, different
purpose, different confidentiality boundary:

- No premium, fine, or expected-damage figures — that's the insurer's
  internal pricing data, not the client's business.
- Framed as a value-add security check delivered as part of the policy
  (the user's own framing: this kind of scan normally costs money and is
  a legitimate thing for the insurer to market, similar to a pentest
  deliverable) — professional tone, remediation-focused, not a raw
  vulnerability dump.
- Every finding becomes a concrete, prioritized action item, not a CVSS
  score. Technical detail (CVE IDs etc.) stays in an appendix for the
  client's own IT/dev team to act on, same "business language body,
  technical appendix" pattern as the agent report.
- Carries its own legal disclaimer: automated, point-in-time, non-
  destructive scan — not a substitute for a full penetration test or
  legal compliance review.
"""

from app.config import ANTHROPIC_API_KEY, INSURER_NAME, LLM_MODEL

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "informational"


async def _remediation_actions_with_llm(findings: list[dict], company_name: str) -> dict[str, str]:
    if not ANTHROPIC_API_KEY or not findings:
        return {}
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        items = "\n".join(
            f"- key={f['key']} | product={f.get('product')} | cve={f.get('cve')} | category={f.get('category')}"
            for f in findings
        )
        prompt = f"""You write short, concrete remediation instructions for {company_name}'s IT team/web
agency, based on a security scan. No CVE jargon in the sentence — describe the fix in plain,
actionable terms (what to update, configure, or change). One imperative sentence per finding.
Return strict JSON: {{"<key>": "<action>", ...}}

Findings:
{items}
"""
        msg = await client.messages.create(
            model=LLM_MODEL, max_tokens=1500, temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text if msg.content else "{}"
        import json
        start, end = text.find("{"), text.rfind("}")
        return json.loads(text[start:end + 1]) if start != -1 else {}
    except Exception:
        return {}


def _fallback_action(f: dict) -> str:
    category = f.get("category", "")
    product = f.get("product") or "the affected system"
    if category in ("iot_ot_cve", "iot_ot_panel"):
        return f"Update or replace the firmware on {product}, and make sure it isn't reachable from the public internet unless absolutely necessary."
    if f.get("cve"):
        return f"Update {product} to the latest vendor-supported version to close the known vulnerability."
    if category == "misconfig":
        return f"Review and harden the configuration of {product} (encryption, headers, or access settings, depending on the finding)."
    return f"Review {product} with your IT provider and apply the vendor's recommended fix."


def _formal_compliance_actions(formal_check: dict) -> list[str]:
    actions = []
    imp = formal_check.get("impressum", {})
    if not imp.get("found"):
        actions.append("Add a legally complete Impressum page, linked from your homepage (required for commercial websites in Germany).")
    elif not imp.get("complete"):
        actions.append("Review your Impressum page — some required details may be missing (address, contact, or management information).")
    cc = formal_check.get("cookie_consent", {})
    if cc.get("violation"):
        actions.append("Install a proper cookie-consent banner (CMP) before any non-essential tracking script or cookie loads on your site.")
    return actions


async def build_client_report(*, company_name: str, domain: str, tier: str,
                               findings: list[dict], risk_tier: str,
                               formal_check: dict) -> str:
    actions_by_key = await _remediation_actions_with_llm(findings, company_name)

    ranked = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(_severity_from_cvss(f.get("cvss") or 0), 5))

    tier_status = {
        "green": "No urgent action items were identified.",
        "yellow": "A few items need attention — none appear to be actively exploited yet.",
        "red": "Several items need prompt attention, including at least one high-severity issue.",
    }[risk_tier]

    lines = []
    lines.append(f"# Cyber-Sicherheitscheck — {company_name}\n")
    lines.append(
        f"*Dieser Sicherheitscheck wurde im Rahmen Ihres Versicherungsschutzes von **{INSURER_NAME}** "
        "durchgeführt — eine technische Prüfung, wie sie sonst als eigenständige Dienstleistung "
        "(z.B. Penetrationstest) separat beauftragt und bezahlt werden müsste.*\n"
    )

    lines.append("## Zusammenfassung\n")
    lines.append(f"{tier_status}\n")
    lines.append(f"Geprüft wurde: {domain} ({'Ihre Website' if tier == 'Tier 0' else 'Ihre Website und Ihre Büro-/Netzwerkinfrastruktur'}).\n")

    lines.append("## Empfohlene Maßnahmen (nach Priorität)\n")
    if not ranked and not formal_check.get("has_violation"):
        lines.append("Keine dringenden Maßnahmen identifiziert. Regelmäßige Updates und Backups bleiben weiterhin wichtig.\n")
    for i, f in enumerate(ranked, 1):
        action = actions_by_key.get(f["key"]) or _fallback_action(f)
        severity = _severity_from_cvss(f.get("cvss") or 0)
        lines.append(f"{i}. **[{severity.upper()}]** {action}")
    for action in _formal_compliance_actions(formal_check):
        lines.append(f"- {action}")
    lines.append("")

    lines.append("## Nächste Schritte\n")
    lines.append(
        f"Bei Fragen zur Umsetzung oder für eine laufende Überwachung Ihrer IT-Sicherheit "
        f"sprechen Sie gerne mit **{INSURER_NAME}** — entsprechende Unterstützungsangebote "
        "können im Rahmen Ihres Vertrags verfügbar sein.\n"
    )

    lines.append("## Rechtlicher Hinweis\n")
    lines.append(
        "Dieser Bericht basiert auf einer automatisierten, nicht-invasiven technischen Prüfung zu "
        "einem bestimmten Zeitpunkt. Er ersetzt keinen vollständigen Penetrationstest, kein "
        "umfassendes Sicherheitsaudit und keine Rechtsberatung. Es kann nicht garantiert werden, "
        "dass alle Schwachstellen erkannt wurden.\n"
    )

    lines.append("## Technischer Anhang\n")
    lines.append("*Für Ihr IT-Team / Ihre Web-Agentur:*\n")
    for f in ranked:
        lines.append(f"- `{f.get('cve') or 'N/A'}` — {f.get('product')} (Kategorie: {f.get('category')})")

    return "\n".join(lines)

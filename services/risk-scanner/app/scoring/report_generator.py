"""
Insurer-facing report: business language up front (fine/damage/premium),
CVE/CVSS technical detail in an appendix. If ANTHROPIC_API_KEY is set, an
LLM writes the plain-language finding descriptions; the numbers themselves
are always computed deterministically in risk_formula.py and never touched
by the LLM — this keeps every figure in the report reproducible by hand.
"""

import asyncio
import json
import logging

from app.config import ANTHROPIC_API_KEY, LLM_MODEL

log = logging.getLogger("report_generator")

# Two sentences per finding is enough output that a single batched call for
# a realistic scan (15-30+ findings) reliably hit max_tokens, truncating the
# JSON mid-response — which silently discarded narrations for EVERY finding
# in the report, not just the ones past the cutoff (a parse failure on the
# whole response). Batching bounds each call's output size and means one
# batch's failure only falls back for that batch's findings.
_BATCH_SIZE = 6


async def _narrate_batch(batch: list[dict], company_name: str) -> dict[str, str]:
    import anthropic
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    items = "\n".join(
        f"- key={f['key']} | product={f.get('product')} | cve={f.get('cve')} | "
        f"cvss={f.get('cvss')} | epss={f.get('epss')} | kev={f.get('kev')} | category={f.get('category')} | "
        f"version_verified={f.get('version_verified', 'n/a')} | "
        f"damage_share_eur={f.get('damage_share_eur', 0):.0f} | counted_in_score={f.get('counted_in_score', False)} | "
        f"description={(f.get('description') or 'NONE — no description available')[:400]}"
        for f in batch
    )
    prompt = f"""You write two-sentence, non-technical explanations of security findings for an
insurance underwriter reviewing {company_name}. No CVE jargon.

Sentence 1 — the concrete consequence: based STRICTLY on the "description" field, state what an
attacker could plausibly achieve (e.g. "could allow an attacker to read or modify the customer
database", "could let an attacker take over the server"). Never invent or guess what a CVE does from
its ID alone — if description is "NONE — no description available", say only that a match was found
for this product/CVE ID and the specific technical detail could not be retrieved; do not fabricate a
plausible-sounding mechanism.

Sentence 2 — the euro figure: if counted_in_score is true, state that this finding accounts for
approximately €{{damage_share_eur formatted with thousands separator}} of the report's total expected
damage figure. If counted_in_score is false, say instead that this finding did not add to the
company's overall score because other, more severe findings in the same risk category already
capped it (name the category) — do not give it a euro figure in that case.

If version_verified is "unknown_scheme" or "no_range_data", add that the affected-version match is
unverified (the scanner could not confirm the installed version is actually within the affected
range) rather than presenting it as a confirmed hit.

Return strict JSON: {{"<key>": "<two sentences as one string>", ...}}

Findings:
{items}
"""
    msg = await client.messages.create(
        model=LLM_MODEL, max_tokens=2048, temperature=0.3,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text if msg.content else "{}"
    if msg.stop_reason == "max_tokens":
        log.warning("report_generator: LLM batch truncated (max_tokens) for %d findings — falling back for this batch", len(batch))
        return {}
    start, end = text.find("{"), text.rfind("}")
    try:
        return json.loads(text[start:end + 1]) if start != -1 else {}
    except json.JSONDecodeError as exc:
        log.warning("report_generator: LLM batch JSON parse failed: %s", exc)
        return {}


async def _narrate_findings_with_llm(findings: list[dict], company_name: str) -> dict[str, str]:
    """Returns {finding_key: business-language sentence}. Best-effort — falls
    back to a template sentence per finding if no API key, or per-batch on
    any error (a failure in one batch never wipes out the others)."""
    if not ANTHROPIC_API_KEY or not findings:
        return {}
    batches = [findings[i:i + _BATCH_SIZE] for i in range(0, len(findings), _BATCH_SIZE)]
    results = await asyncio.gather(
        *(_narrate_batch(b, company_name) for b in batches), return_exceptions=True
    )
    merged: dict[str, str] = {}
    for r in results:
        if isinstance(r, dict):
            merged.update(r)
        elif isinstance(r, Exception):
            log.warning("report_generator: LLM batch failed: %s", r)
    return merged


def _damage_clause(f: dict) -> str:
    if f.get("counted_in_score"):
        return f" This finding accounts for approximately €{f.get('damage_share_eur', 0):,.0f} of the total expected damage figure above.".replace(",", ".")
    return f" This finding did not add to the overall score — other, more severe findings in the '{f.get('category')}' category already capped it."


def _fallback_sentence(f: dict) -> str:
    where = f.get("product") or "an exposed service"
    cve = f.get("cve")
    if not cve:
        return f"{where} shows a detectable misconfiguration flagged during the scan; see the technical appendix for detail.{_damage_clause(f)}"
    unverified = " (version match unverified — see appendix)" if f.get("version_verified") in ("unknown_scheme", "no_range_data") else ""
    if f.get("kev"):
        return f"{where} has a known, actively exploited vulnerability ({cve}){unverified} — this is a live attack path, not a theoretical risk.{_damage_clause(f)}"
    if (f.get("epss") or 0) >= 0.5:
        return f"{where} has a vulnerability ({cve}){unverified} with a high real-world probability of exploitation.{_damage_clause(f)}"
    return f"{where} has a matched vulnerability ({cve}){unverified}; see the technical appendix for the vendor description.{_damage_clause(f)}"


async def build_report(*, company_name: str, domain: str, industry: str, tier: str,
                        findings: list[dict], scoring: dict, damage: float,
                        fine: dict, ransom: dict, premium: tuple[float, float], risk_tier: str,
                        recon: dict, formal_check: dict,
                        data_quality_warnings: list[str] | None = None) -> str:
    narrations = await _narrate_findings_with_llm(findings, company_name)

    lines = []
    lines.append(f"# Cyber-Risk Assessment — {company_name}\n")
    lines.append(f"**Domain:** {domain}  |  **Industry:** {industry}  |  **Scan depth:** {tier}\n")

    if data_quality_warnings:
        lines.append("> **⚠ Datenqualität — vor Interpretation der Ergebnisse lesen**")
        for w in data_quality_warnings:
            lines.append(f"> - {w}")
        lines.append(
            "> Die untenstehenden Zahlen basieren nur auf den Datenquellen, die tatsächlich "
            "verfügbar waren. Ein 'sauberes' Ergebnis in einem betroffenen Bereich bedeutet hier "
            "möglicherweise nur, dass dort nicht geprüft werden konnte — nicht, dass keine Risiken bestehen.\n"
        )

    tier_word = {"green": "Niedriges Risiko", "yellow": "Mittleres Risiko", "red": "Erhöhtes Risiko"}[risk_tier]
    lines.append("## 1. Executive Summary\n")
    lines.append(f"- **Risk tier:** {risk_tier.upper()} — {tier_word}")
    lines.append(f"- **Risk multiplier:** {scoring['raw_score_info']['multiplier']}x (raw score {scoring['raw_score_info']['raw_score']})")
    lines.append(f"- **Erwarteter Schaden (expected loss):** ca. €{damage:,.0f}".replace(",", "."))
    lines.append(f"- **Empfohlene Prämien-Spanne:** €{premium[0]:,.0f} – €{premium[1]:,.0f} *(erfordert Freigabe durch Underwriter/Aktuar)*".replace(",", "."))
    if fine.get("available"):
        lines.append(f"- **DSGVO-Bußgeld-Exposure:** €{fine['low']:,.0f} – €{fine['high']:,.0f} (DSK-Bußgeldkonzept, *Berechnungshilfe, Gerichte nicht daran gebunden*)".replace(",", "."))
        nis2 = fine.get("nis2") or {}
        if nis2.get("applicable"):
            lines.append(f"- **NIS2-Bußgeld-Exposure:** €{nis2['low']:,.0f} – €{nis2['high']:,.0f} (Sektor-Einordnung noch offen)".replace(",", "."))
        elif nis2:
            lines.append(f"- **NIS2-Bußgeld-Exposure:** voraussichtlich nicht anwendbar ({nis2['basis']})")
    else:
        lines.append("- **Bußgeld-Exposure:** nicht berechnet — Jahresumsatz wurde nicht angegeben")
    if ransom.get("available"):
        lines.append(f"- **Cyber-Extortion-Sublimit (Richtwert):** €{ransom['low']:,.0f} – €{ransom['high']:,.0f}".replace(",", "."))
    lines.append("")

    lines.append("## 2. Company Profile\n")
    lines.append(f"- Company: {company_name}")
    lines.append(f"- Domain: {domain}")
    lines.append(f"- Industry: {industry}")
    lines.append(f"- Scan tier: {tier} ({'domain-only OSINT' if tier == 'Tier 0' else 'includes office IP / Shodan infrastructure check'})")
    lines.append("")

    lines.append("## 3. Findings (business language)\n")
    if not findings:
        lines.append("No exploitable weaknesses with a matched CVE were found during this scan. This does not guarantee absence of risk — it reflects what was detectable within the current scan tier.\n")
    ranked_findings = sorted(findings, key=lambda f: f.get("damage_share_eur", 0), reverse=True)
    for f in ranked_findings:
        sentence = narrations.get(f["key"]) or _fallback_sentence(f)
        share = f.get("damage_share_eur", 0)
        share_tag = f"**≈€{share:,.0f}**".replace(",", ".") if f.get("counted_in_score") else "*(nicht im Score erfasst)*"
        lines.append(f"- **[{f.get('category')}]** {share_tag} — {sentence}")
    lines.append("")

    lines.append("## 3b. Formale Anforderungen (Impressum / Cookie-Consent)\n")
    lines.append("*Heuristische Mustererkennung — keine Rechtsberatung, keine vollständige TMG/DDG/TTDSG-Prüfung.*\n")
    imp = formal_check.get("impressum", {})
    if not imp.get("found"):
        lines.append("- **Impressum:** nicht auffindbar (kein Link auf der Startseite erkannt)")
    elif not imp.get("complete"):
        lines.append(f"- **Impressum:** gefunden, aber möglicherweise unvollständig — {', '.join(imp.get('missing', []))}")
    else:
        lines.append("- **Impressum:** gefunden, Pflichtangaben erkannt")

    cc = formal_check.get("cookie_consent", {})
    if not cc.get("checked"):
        lines.append("- **Cookie-Consent:** nicht prüfbar (Startseite nicht erreichbar)")
    elif cc.get("violation"):
        if cc.get("pre_consent_tracking_cookies"):
            lines.append(f"- **Cookie-Consent:** Tracking-Cookies vor Einwilligung gesetzt ({', '.join(cc['pre_consent_tracking_cookies'])})")
        else:
            lines.append("- **Cookie-Consent:** Tracking-Skripte ohne erkennbares Consent-Tool (CMP) gefunden")
    else:
        lines.append("- **Cookie-Consent:** kein Verstoß erkannt")
    lines.append("")

    lines.append("## 4. Loss & Fine Calculation (transparent formula)\n")
    lines.append("```")
    lines.append(f"expected_damage = base_loss(EUR 83,000) x industry_factor x multiplier")
    lines.append(f"                = EUR {damage:,.0f}".replace(",", "."))
    lines.append(f"multiplier      = 1 + (M_max-1) x (1 - e^(-raw_score/k))  =  {scoring['raw_score_info']['multiplier']}")
    lines.append(f"raw_score       = {scoring['raw_score_info']['raw_score']}  (findings by category + regulatory-gap points: {scoring['raw_score_info']['reg_gap_points']})")
    lines.append("```")
    lines.append("")

    if fine.get("available") and fine.get("dsgvo", {}).get("available"):
        d = fine["dsgvo"]
        lines.append("**DSGVO-Bußgeld — DSK-Bußgeldkonzept (2019), Konferenz der Datenschutzaufsichtsbehörden:**")
        lines.append("```")
        lines.append(f"Tagessatz (Jahresumsatz-Größenklasse / 360)  = EUR {d['tagessatz_eur']:,.0f}".replace(",", "."))
        if d.get("material_severity"):
            lo, hi = d["material_fine_range_eur"]
            lines.append(f"Materieller Verstoß (Art. 83(5)/(6), z.B. Art. 32 — unzureichende TOMs): {d['material_severity']}")
            lines.append(f"  -> Bußgeld-Spanne: EUR {lo:,.0f} - EUR {hi:,.0f}".replace(",", "."))
        else:
            lines.append("Materieller Verstoß: keiner erkannt (kein CVE-belegter Fund)")
        if d.get("formal_severity"):
            lo, hi = d["formal_fine_range_eur"]
            lines.append(f"Formeller Verstoß (Art. 83(4), z.B. Impressum/Cookie-Banner): {d['formal_severity']}")
            lines.append(f"  -> Bußgeld-Spanne: EUR {lo:,.0f} - EUR {hi:,.0f}".replace(",", "."))
        else:
            lines.append("Formeller Verstoß: nicht geprüft (M1 prüft aktuell keine Impressum-/Cookie-Banner-Vollständigkeit)")
        lines.append("```")
        lines.append(
            "*Rechtlicher Hinweis: Das DSK-Bußgeldkonzept (2019) ist ein Berechnungsschema der "
            "deutschen Datenschutzaufsichtsbehörden, kein Gesetz — Gerichte sind daran nicht gebunden "
            "und haben Aufsichtsbehörden-Bußgelder auf dieser Grundlage bereits nach oben wie unten "
            "korrigiert, insbesondere bei größeren Unternehmen. Stand der Recherche: 21.08.2026, kein "
            "aktualisiertes Konzept seit 2019 veröffentlicht.*\n"
        )

    nis2 = fine.get("nis2") or {}
    if nis2.get("applicable"):
        lines.append(
            "*NIS2UmsuCG (in Kraft seit 06.12.2025): Bußgeldrahmen 'wichtige Einrichtung' "
            "1,4%/EUR 7 Mio., 'wesentliche Einrichtung' 2%/EUR 10 Mio. (jeweils der höhere Betrag). "
            "Die genaue Einordnung hängt von der Sektor-Zugehörigkeit ab (§28 BSIG), die hier noch "
            "nicht geprüft wurde.*\n"
        )

    if ransom.get("available"):
        lines.append(f"**Cyber-Extortion-Sublimit:** {ransom['basis']}\n")

    lines.append("")

    lines.append("## 5. Recommendation\n")
    lines.append("This is an AI-generated recommendation. Final pricing and acceptance decisions require sign-off by a licensed underwriter/actuary at the insurer.\n")

    lines.append("## Appendix — Technical Detail\n")
    lines.append(f"Subdomains discovered: {recon.get('subdomains_found', 0)}\n")
    for f in findings:
        verified = f.get("version_verified", "n/a")
        line = f"- `{f.get('cve') or 'N/A'}` — CVSS {f.get('cvss')}, EPSS {f.get('epss')}, KEV={f.get('kev')}, product={f.get('product')}, category={f.get('category')}, version_verified={verified}"
        lines.append(line)
        if f.get("description"):
            lines.append(f"  > {f['description']}")
    lines.append("")
    lines.append("### Category breakdown")
    for cat, info in scoring["raw_score_info"]["by_category"].items():
        lines.append(f"- {cat}: weight={info['weight']}, top scores={info['top_scores']}, category_score={info['category_score']}")

    return "\n".join(lines)

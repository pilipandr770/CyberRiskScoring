"""
Pre-filled Versicherungsantrag (insurance application/proposal) — built on
the real structure of GDV's AVB Cyber 2024 model conditions (the standard
German market reference most insurers base their own terms on), not an
invented layout. Source: "Allgemeine Versicherungsbedingungen für die
Cyberrisiko-Versicherung (AVB Cyber)", GDV, Stand Februar 2024.

The AVB's coverage is modular (Bausteine):
  A2  Service-/Kosten-Baustein   — forensics / crisis-management costs
  A3  Drittschaden-Baustein      — third-party liability
  A4-1 Betriebsunterbrechung     — business interruption
  A4-2 Wiederherstellung von Daten — data restoration
  (+ common market extension: Cyber-Erpressung / extortion sublimit)

Default sums insured/premium/deductible are generic-layer starting values
— clearly marked editable, not a finished quote. The agent adjusts them
in the form before generating the printable document.

A1-16 of the AVB lists the policyholder's pre-loss IT-security duties
(Obliegenheiten) — individual accounts + password rules, extra protection
for internet-facing/mobile devices, current malware protection, timely
patch management, weekly isolated backups. That list maps almost exactly
onto what M1 already checks (has_mfa, patch/CVE status, has_tested_backups)
— check_obliegenheiten() below cross-references the scan against the real
duty text so the agent sees compliance status against the actual policy
language, not a generic security checklist.
"""

# Common German SME cyber sum-insured tiers — the offer rounds up to the
# nearest one rather than proposing an arbitrary figure.
_SUM_INSURED_TIERS = [250_000, 500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000]


def _round_to_tier(value: float) -> float:
    for tier in _SUM_INSURED_TIERS:
        if value <= tier:
            return tier
    return _SUM_INSURED_TIERS[-1]


def default_contract_fields(*, assessment, scan: dict, ransom: dict) -> dict:
    total_sum = _round_to_tier(scan["expected_damage_eur"] * 1.5)  # headroom above the point estimate

    premium_mid = round((scan["premium_range_low_eur"] + scan["premium_range_high_eur"]) / 2, -2)
    deductible = max(500, round(total_sum * 0.01, -2))

    extortion_sum = _round_to_tier(ransom["high"]) if ransom.get("available") else min(total_sum, 250_000)

    return {
        "policyholder_name": assessment.company_name,
        "policyholder_hrb": assessment.hrb_number or "",
        "policyholder_domain": assessment.domain,
        "insurer_name_placeholder": "[VERSICHERER EINTRAGEN]",
        "policy_start_placeholder": "[BEGINNDATUM]",
        "policy_term_years": 1,
        "total_sum_insured_eur": total_sum,
        "sums": {
            "a3_drittschaden": total_sum,
            "a4_1_betriebsunterbrechung": round(total_sum * 0.4, -3),
            "a4_2_datenwiederherstellung": round(total_sum * 0.2, -3),
            "a2_forensik_kosten": min(round(total_sum * 0.3, -3), 250_000),
            "cyber_erpressung": extortion_sum,
        },
        "haftzeit_bu_months": 3,
        "wartezeit_bu_hours": 12,
        "deductible_eur": deductible,
        "premium_annual_eur": premium_mid,
        "payment_frequency": "jährlich",
        "avb_reference": "AVB Cyber (GDV-Musterbedingungen, Stand Februar 2024)",
    }


def check_obliegenheiten(*, assessment, findings: list[dict]) -> list[dict]:
    """Cross-references the AVB Cyber's real A1-16 pre-loss duties against
    what this scan actually found — 'erfüllt' / 'auffällig' / 'nicht
    bestätigt', each citing the specific AVB clause, not a generic
    security-hygiene label."""
    items = []

    mfa = assessment.has_mfa or "unknown"
    items.append({
        "clause": "A1-16.1 b) — Zusätzlicher Zugriffsschutz für internetseitig erreichbare Systeme (z.B. 2FA)",
        "status": "erfüllt" if mfa == "yes" else ("auffällig" if mfa == "no" else "nicht bestätigt"),
        "detail": "Selbstauskunft des Versicherungsnehmers." if mfa != "unknown" else "Nicht abgefragt/keine Angabe.",
    })

    unpatched = [f for f in findings if f.get("cve") and (f.get("cvss") or 0) >= 7.0]
    items.append({
        "clause": "A1-16.1 d) — Patch-Management, zeitnahe Installation von Sicherheitsupdates",
        "status": "auffällig" if unpatched else "erfüllt (im Scan-Umfang)",
        "detail": (
            f"{len(unpatched)} offene(s) hochkritische(s) CVE(s) im Scan gefunden, u.a. {unpatched[0].get('cve')}."
            if unpatched else "Keine hochkritischen offenen CVEs im Scan-Umfang gefunden."
        ),
    })

    backups = assessment.has_tested_backups or "unknown"
    items.append({
        "clause": "A1-16.1 e) — Mindestens wöchentlicher, getrennter Sicherungsprozess",
        "status": "erfüllt" if backups == "yes" else ("auffällig" if backups == "no" else "nicht bestätigt"),
        "detail": "Selbstauskunft des Versicherungsnehmers." if backups != "unknown" else "Nicht abgefragt/keine Angabe.",
    })

    return items

"""Renders the Versicherungsantrag document text from (possibly agent-
edited) contract fields + the Obliegenheiten cross-check. Shared by the
live editable preview and the final PDF so both always match."""


def render_contract_markdown(*, fields: dict, obliegenheiten: list[dict], industry: str, tier: str) -> str:
    def eur(v) -> str:
        return f"€{float(v):,.0f}".replace(",", ".")

    lines = []
    lines.append("# Versicherungsantrag — Cyberrisiko-Versicherung\n")
    lines.append(f"*Grundlage: {fields['avb_reference']}*\n")

    lines.append("## Vertragsparteien\n")
    lines.append(f"- **Versicherer:** {fields['insurer_name_placeholder']}")
    lines.append(f"- **Versicherungsnehmer:** {fields['policyholder_name']}")
    if fields.get("policyholder_hrb"):
        lines.append(f"  - HRB: {fields['policyholder_hrb']}")
    lines.append(f"  - Domain/Betrieb: {fields['policyholder_domain']} ({industry}, Scan-Tiefe: {tier})")
    lines.append("")

    lines.append("## Vertragslaufzeit\n")
    lines.append(f"- Versicherungsbeginn: {fields['policy_start_placeholder']}")
    lines.append(f"- Laufzeit: {fields['policy_term_years']} Jahr(e), danach Verlängerung gemäß AVB Cyber Abschnitt B2")
    lines.append("")

    lines.append("## Versicherungssummen nach Baustein\n")
    lines.append("| Baustein | Versicherungssumme |")
    lines.append("|---|---|")
    lines.append(f"| A2 — Service-/Kosten-Baustein (Forensik, Krisenmanagement) | {eur(fields['sums']['a2_forensik_kosten'])} |")
    lines.append(f"| A3 — Drittschaden-Baustein (Haftpflicht) | {eur(fields['sums']['a3_drittschaden'])} |")
    lines.append(f"| A4-1 — Betriebsunterbrechung (Haftzeit {fields['haftzeit_bu_months']} Monate, Wartezeit {fields['wartezeit_bu_hours']}h) | {eur(fields['sums']['a4_1_betriebsunterbrechung'])} |")
    lines.append(f"| A4-2 — Wiederherstellung von Daten | {eur(fields['sums']['a4_2_datenwiederherstellung'])} |")
    lines.append(f"| Cyber-Erpressung / Lösegeld (Erweiterung) | {eur(fields['sums']['cyber_erpressung'])} |")
    lines.append(f"| **Gesamtversicherungssumme** | **{eur(fields['total_sum_insured_eur'])}** |")
    lines.append("")

    lines.append("## Beitrag\n")
    lines.append(f"- **Jahresprämie (Vorschlag):** {eur(fields['premium_annual_eur'])}")
    lines.append(f"- Zahlungsweise: {fields['payment_frequency']}")
    lines.append(f"- Selbstbeteiligung: {eur(fields['deductible_eur'])} je Versicherungsfall")
    lines.append("")

    lines.append("## Obliegenheiten-Check (AVB Cyber, Abschnitt A1-16)\n")
    lines.append("*Abgleich der vertraglichen IT-Sicherheits-Obliegenheiten mit den Ergebnissen der technischen Prüfung — vor Vertragsschluss zu klären, wo 'auffällig'/'nicht bestätigt' vermerkt ist.*\n")
    lines.append("| Klausel | Status | Detail |")
    lines.append("|---|---|---|")
    for item in obliegenheiten:
        lines.append(f"| {item['clause']} | **{item['status']}** | {item['detail']} |")
    lines.append("")

    lines.append("## Unterschriften\n")
    lines.append("Ort, Datum: ______________________\n")
    lines.append("")
    lines.append("Versicherungsnehmer: ______________________          Versicherer/Vertreter: ______________________\n")

    lines.append("## Hinweis\n")
    lines.append(
        "Dieser Antrag ist ein automatisiert erstellter Entwurf auf Basis einer technischen Risikoeinschätzung. "
        "Versicherungssummen, Prämie und Selbstbeteiligung sind Vorschlagswerte und bedürfen der Prüfung und "
        f"Freigabe durch {fields['insurer_name_placeholder']} vor Vertragsschluss. Es gelten ergänzend die "
        f"vollständigen {fields['avb_reference']}."
    )

    return "\n".join(lines)

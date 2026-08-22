"""
German DSK "Bußgeldkonzept" (2019) — the official methodology the German
data protection authorities' conference (Datenschutzkonferenz) publishes
for calculating GDPR fines against companies. Source: "Konzept der
unabhängigen Datenschutzaufsichtsbehörden des Bundes und der Länder zur
Bußgeldzumessung in Verfahren gegen Unternehmen", 14.10.2019 —
https://www.datenschutzkonferenz-online.de/media/ah/20191016_bu%C3%9Fgeldkonzept.pdf

Five official steps: (1) size class from worldwide prior-year turnover,
(2) average turnover of that subgroup, (3) daily rate (Tagessatz) = avg
turnover / 360, (4) multiply by a severity factor that depends on whether
the violation is formal (Art. 83(4) DSGVO, cap 2%/€10M — e.g. an
incomplete Impressum, a defective cookie-consent banner) or material
(Art. 83(5)/(6), cap 4%/€20M — e.g. inadequate Art. 32 technical/
organisational security measures, which is where "didn't patch the shop
software for 5 years and got breached" lands), (5) case-specific
adjustment (cooperation, insolvency risk, procedure length — this last
step requires human judgment and stays with the underwriter, not modeled
here).

M1 currently only detects the material-violation side (real CVEs/
misconfig via active scanning) — it does not yet check for formal
violations like a missing Impressum or a defective cookie banner. That's
a concrete, buildable addition (presence-detection, not full legal
review) flagged in classify_formal_severity() below; until it exists,
callers pass has_formal_violation=False and that half of the fine is 0.
"""

import math

# Table 1+2 combined: (upper bound of the subgroup's turnover range in EUR)
# -> that subgroup's official average turnover. A company's turnover is
# bucketed into the first range it falls under. Above €500M, DSK uses the
# company's actual turnover directly rather than a subgroup average.
_SUBGROUP_UPPER_TO_AVERAGE = [
    (700_000, 350_000),
    (1_400_000, 1_050_000),
    (2_000_000, 1_700_000),
    (5_000_000, 3_500_000),
    (7_500_000, 6_250_000),
    (10_000_000, 8_750_000),
    (12_500_000, 11_250_000),
    (15_000_000, 13_750_000),
    (20_000_000, 17_500_000),
    (25_000_000, 22_500_000),
    (30_000_000, 27_500_000),
    (40_000_000, 35_000_000),
    (50_000_000, 45_000_000),
    (75_000_000, 62_500_000),
    (100_000_000, 87_500_000),
    (200_000_000, 150_000_000),
    (300_000_000, 250_000_000),
    (400_000_000, 350_000_000),
    (500_000_000, 450_000_000),
]

# Table 4 — severity factor ranges, formal vs material violations.
_SEVERITY_FACTORS = {
    "leicht": {"formal": (1, 2), "material": (1, 4)},
    "mittel": {"formal": (2, 4), "material": (4, 8)},
    "schwer": {"formal": (4, 6), "material": (8, 12)},
    "sehr_schwer": {"formal": (6, 6), "material": (12, 14.4)},  # 14.4 = exactly 4% (the legal ceiling)
}

STATUTORY_CAP_PCT = {"formal": 0.02, "material": 0.04}  # Art. 83(4) vs Art. 83(5)/(6)


def average_turnover_for(turnover_eur: float) -> float:
    for upper_bound, avg in _SUBGROUP_UPPER_TO_AVERAGE:
        if turnover_eur <= upper_bound:
            return avg
    return turnover_eur  # >€500M: DSK computes from the actual figure directly


def daily_rate(turnover_eur: float) -> float:
    """Table 3: Tagessatz = average subgroup turnover / 360, rounded up."""
    return math.ceil(average_turnover_for(turnover_eur) / 360)


def classify_material_severity(findings: list[dict]) -> tuple[str | None, float]:
    """
    Maps M1's existing CVSS/EPSS/KEV signal onto the DSK's leicht/mittel/
    schwer/sehr-schwer scale for MATERIAL violations — inadequate Art. 32
    security measures is the ground almost all of our findings sit under.
    Returns (severity_label, factor); factor is the midpoint of that
    severity's range (a single headline number, though the range is kept
    in the caller's output for transparency). (None, 0.0) if no CVE-backed
    finding exists — a clean scan shouldn't imply a material violation.
    """
    cve_findings = [f for f in findings if f.get("cve")]
    if not cve_findings:
        return None, 0.0

    max_cvss = max((f.get("cvss") or 0) for f in cve_findings)
    max_epss = max((f.get("epss") or 0) for f in cve_findings)
    any_kev = any(f.get("kev") for f in cve_findings)

    if any_kev and max_cvss >= 9:
        severity = "sehr_schwer"
    elif max_cvss >= 9 or (max_cvss >= 7 and max_epss >= 0.5):
        severity = "schwer"
    elif max_cvss >= 7 or max_epss >= 0.2:
        severity = "mittel"
    else:
        severity = "leicht"

    low, high = _SEVERITY_FACTORS[severity]["material"]
    return severity, (low + high) / 2


def classify_formal_severity(has_formal_violation: bool) -> str | None:
    return "leicht" if has_formal_violation else None


def _fine_range(severity: str | None, kind: str, tagessatz: float, turnover_eur: float) -> tuple[float, float]:
    if not severity:
        return 0.0, 0.0
    low_factor, high_factor = _SEVERITY_FACTORS[severity][kind]
    cap = turnover_eur * STATUTORY_CAP_PCT[kind]
    return min(tagessatz * low_factor, cap), min(tagessatz * high_factor, cap)


def compute_fine(turnover_eur: float | None, findings: list[dict], has_formal_violation: bool = False) -> dict:
    if not turnover_eur:
        return {
            "available": False, "low": None, "high": None, "estimate": None,
            "basis": "DSK-Bußgeldkonzept (2019)",
            "note": "Jahresumsatz nicht angegeben — keine Berechnung möglich",
        }

    tagessatz = daily_rate(turnover_eur)
    material_severity, _ = classify_material_severity(findings)
    formal_severity = classify_formal_severity(has_formal_violation)

    m_low, m_high = _fine_range(material_severity, "material", tagessatz, turnover_eur)
    f_low, f_high = _fine_range(formal_severity, "formal", tagessatz, turnover_eur)

    total_low, total_high = m_low + f_low, m_high + f_high
    return {
        "available": True,
        "tagessatz_eur": round(tagessatz, 0),
        "material_severity": material_severity,
        "material_fine_range_eur": (round(m_low, 0), round(m_high, 0)),
        "formal_severity": formal_severity,
        "formal_fine_range_eur": (round(f_low, 0), round(f_high, 0)),
        "low": round(total_low, 0),
        "high": round(total_high, 0),
        "estimate": round((total_low + total_high) / 2, 0),
        "basis": "DSK-Bußgeldkonzept (2019): Tagessatz × Schweregrad-Faktor, je Verstoßart gedeckelt auf 2%/4% Jahresumsatz",
    }

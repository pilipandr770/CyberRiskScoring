"""
Risk-multiplier formula: findings -> a single explainable number, per the
formula agreed for M1->M2 (see project memory). Every intermediate value
is kept in the returned dict so the report can show its work.
"""

import math

from app.config import (
    BASE_LOSS_EUR, INDUSTRY_FACTOR, MULTIPLIER_MAX, MULTIPLIER_K,
    MULTIPLIER_FLOOR_CLEAN, NIS2_FINE_PCT, CATEGORY_WEIGHTS,
    RANSOM_PCT_OF_TURNOVER, RANSOM_FLOOR_EUR, RANSOM_CEILING_EUR,
    NIS2_SIZE_THRESHOLD_TURNOVER_EUR, NIS2_SIZE_THRESHOLD_EMPLOYEE_BANDS,
    PREMIUM_TARGET_LOSS_RATIO,
)
from app.scoring import dsk_bussgeld

_TOP_N_PER_CATEGORY = 5


def finding_score(cvss: float, epss: float) -> float:
    """CVSS scaled by real-world exploitation likelihood (EPSS), floored so a
    finding with 0 EPSS isn't zeroed out."""
    return round(cvss * (0.5 + 0.5 * epss), 2)


def aggregate_raw_score(findings: list[dict], reg_gap_points: float) -> dict:
    """
    findings: [{"category": str, "cvss": float, "epss": float, "kev": bool, ...}]
    category must be a key in CATEGORY_WEIGHTS.
    Returns {"raw_score": float, "by_category": {...}, "reg_gap_points": float}
    """
    by_category: dict[str, list[float]] = {}
    for f in findings:
        cat = f.get("category", "internet_facing_generic")
        score = finding_score(f.get("cvss", 0.0), f.get("epss", 0.0))
        if f.get("kev"):
            score *= 1.15  # small explicit bump for confirmed active exploitation
        by_category.setdefault(cat, []).append(round(score, 2))

    category_scores = {}
    raw_score = 0.0
    for cat, scores in by_category.items():
        top_scores = sorted(scores, reverse=True)[:_TOP_N_PER_CATEGORY]
        weight = CATEGORY_WEIGHTS.get(cat, 1.0)
        cat_score = weight * sum(top_scores)
        category_scores[cat] = {"weight": weight, "top_scores": top_scores, "category_score": round(cat_score, 2)}
        raw_score += cat_score

    raw_score += reg_gap_points

    return {
        "raw_score": round(raw_score, 2),
        "by_category": category_scores,
        "reg_gap_points": reg_gap_points,
    }


def raw_score_to_multiplier(raw_score: float) -> float:
    if raw_score <= 0.5:
        return MULTIPLIER_FLOOR_CLEAN
    return round(1 + (MULTIPLIER_MAX - 1) * (1 - math.exp(-raw_score / MULTIPLIER_K)), 2)


def compliance_gap_points(assessment) -> float:
    """
    Small fixed-point checklist — generic layer, documented assumptions.
    assessment is the ClientAssessment ORM row (or any object with these attrs).
    """
    points = 0.0
    if (assessment.has_mfa or "unknown") == "no":
        points += 3
    if (assessment.has_tested_backups or "unknown") == "no":
        points += 2
    if (assessment.prior_incident or "no") == "yes":
        points += 3
    return points


def expected_damage(industry: str, multiplier: float) -> float:
    factor = INDUSTRY_FACTOR.get(industry, INDUSTRY_FACTOR["other"])
    return round(BASE_LOSS_EUR * factor * multiplier, 0)


def _nis2_applies(turnover_eur: float | None, employee_band: str | None) -> bool:
    """§28 BSIG size gate: >=50 employees OR >€10M turnover, AND a
    regulated sector — sector isn't checked yet (no NACE mapping built),
    so this only gates on size; a size-qualifying company still gets a
    sector caveat in the output rather than a hard "not applicable"."""
    if turnover_eur and turnover_eur > NIS2_SIZE_THRESHOLD_TURNOVER_EUR:
        return True
    if employee_band in NIS2_SIZE_THRESHOLD_EMPLOYEE_BANDS:
        return True
    return False


def fine_exposure(turnover_eur: float | None, findings: list[dict], has_formal_violation: bool = False,
                   employee_band: str | None = None) -> dict:
    """
    DSGVO fine: the actual DSK-Bußgeldkonzept (2019) methodology — see
    dsk_bussgeld.py. Confirmed still current (no update published); courts
    aren't bound by it though, so it's a calculation-aid estimate, not a
    guaranteed figure — that caveat must stay visible in the report.

    NIS2 fine: NIS2UmsuCG is confirmed real, current German law (in force
    2025-12-06) with published percentage/cap figures — this is no longer
    a rough guess. But NIS2 only applies above a size threshold and within
    regulated sectors (§28 BSIG); most of this product's actual target
    segment (Kleinst-/kleine GmbH) falls below the threshold entirely, so
    "not applicable" is the common, correct answer here, not a smaller
    number. Shown as a range across "wichtige"/"wesentliche" classification
    since sector isn't checked yet — which tier applies isn't guessed at.
    """
    dsgvo = dsk_bussgeld.compute_fine(turnover_eur, findings, has_formal_violation)
    if not turnover_eur:
        return {"available": False, "low": None, "high": None, "estimate": None, "dsgvo": dsgvo, "nis2": None}

    if not _nis2_applies(turnover_eur, employee_band):
        nis2 = {
            "applicable": False,
            "basis": "NIS2UmsuCG (§28 BSIG): Größenschwelle (>=50 Mitarbeiter oder >EUR 10 Mio. Umsatz) nicht erreicht — voraussichtlich nicht anwendbar",
        }
    else:
        wichtige_pct, wichtige_cap = NIS2_FINE_PCT["wichtige"]
        wesentliche_pct, wesentliche_cap = NIS2_FINE_PCT["wesentliche"]
        nis2_low = min(wichtige_pct * turnover_eur, wichtige_cap)
        nis2_high = min(wesentliche_pct * turnover_eur, wesentliche_cap)
        nis2 = {
            "applicable": True,
            "low": round(nis2_low, 0),
            "high": round(max(nis2_low, nis2_high), 0),
            "basis": "NIS2UmsuCG Art. 28 BSIG — Spanne 'wichtige' (1,4%/EUR 7 Mio.) bis 'wesentliche' Einrichtung (2%/EUR 10 Mio.); Sektor-Einordnung noch nicht geprüft",
            "confidence": "medium",
        }

    return {
        "available": True,
        "low": dsgvo["low"],
        "high": dsgvo["high"],
        "estimate": dsgvo["estimate"],
        "dsgvo": dsgvo,
        "nis2": nis2,
    }


def ransom_exposure(turnover_eur: float | None) -> dict:
    """
    Cyber-extortion sublimit estimate — deliberately separate from
    expected_damage (which already prices in incident probability via the
    risk multiplier). Ransomware operators commonly size demands as a
    percentage of the victim's revenue (documented IR-industry practice,
    e.g. Coveware's case reporting) — this is a generic-layer benchmark,
    not a precise prediction, and should read as "plausible demand size if
    a ransomware event occurs," useful for setting a policy sublimit.
    """
    if not turnover_eur:
        return {"available": False, "low": None, "high": None, "basis": "% of turnover (industry IR benchmark)"}

    low = max(RANSOM_FLOOR_EUR, min(RANSOM_PCT_OF_TURNOVER[0] * turnover_eur, RANSOM_CEILING_EUR))
    high = max(RANSOM_FLOOR_EUR, min(RANSOM_PCT_OF_TURNOVER[1] * turnover_eur, RANSOM_CEILING_EUR))
    return {
        "available": True,
        "low": round(low, 0),
        "high": round(high, 0),
        "basis": f"{RANSOM_PCT_OF_TURNOVER[0]*100:.0f}–{RANSOM_PCT_OF_TURNOVER[1]*100:.0f}% des Jahresumsatzes (IR-Branchenbenchmark), Floor/Ceiling €{RANSOM_FLOOR_EUR:,.0f}/€{RANSOM_CEILING_EUR:,.0f}".replace(",", "."),
    }


def premium_range(expected_damage_eur: float) -> tuple[float, float]:
    """
    Premium = expected loss / target loss ratio — anchored to GDV's
    published Schaden-Kosten-Quote (combined ratio) for the German cyber
    insurance market: 64.7% (2020), 123.7% (2021, crisis year), 77.7%
    (2022), 97% (2023). Source: GDV market statistics/"Cyberversicherer
    kehren in die Gewinnzone zurück" (confirmed 2026-08-21).
    2021 was clearly unsustainable; pricing to a target loss ratio BELOW
    the volatile historical average builds in a margin rather than
    repricing last year's actuals. PREMIUM_TARGET_LOSS_RATIO brackets a
    target range (55%-75%) around the two healthiest realized years —
    still a generic-layer assumption pending real claims data, but now
    grounded in a published market figure instead of an arbitrary 15-25%.
    Still explicitly NOT an actuarial premium — requires underwriter/
    actuary sign-off before binding.
    """
    low_ratio, high_ratio = PREMIUM_TARGET_LOSS_RATIO
    return round(expected_damage_eur / high_ratio, 0), round(expected_damage_eur / low_ratio, 0)


def risk_tier_label(multiplier: float) -> str:
    if multiplier <= 1.1:
        return "green"
    if multiplier <= 2.2:
        return "yellow"
    return "red"

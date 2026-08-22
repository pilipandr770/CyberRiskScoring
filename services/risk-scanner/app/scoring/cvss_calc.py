"""
CVSS v3.1 vector parsing + deterministic scoring.

Ported from BB_Assist (backend/services/cvss_calculator.py). Adds
score_from_number() for the common case here where a source (Shodan, NVD
summary data) hands us a bare CVSS score with no vector string.
"""

import re
from typing import Optional

from cvss import CVSS3
from cvss.exceptions import CVSS3MalformedError

_VECTOR_RE = re.compile(r"CVSS:3\.[01](?:/[A-Z]{1,3}:[A-Za-z]{1,2})+")

_SEVERITY_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]


def severity_from_score(score: float) -> str:
    for threshold, severity in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "informational"


def extract_vector(text: str) -> Optional[str]:
    match = _VECTOR_RE.search(text or "")
    return match.group(0) if match else None


def compute_from_vector(vector: str) -> Optional[tuple[float, str]]:
    if not vector:
        return None
    try:
        c = CVSS3(vector)
        score = round(float(c.base_score), 1)
        return score, severity_from_score(score)
    except (CVSS3MalformedError, Exception):
        return None  # noqa: E722 — any malformed vector should fall back, not crash the scan


def score_from_number(score: Optional[float]) -> Optional[tuple[float, str]]:
    if score is None:
        return None
    try:
        score = round(float(score), 1)
        return score, severity_from_score(score)
    except (TypeError, ValueError):
        return None

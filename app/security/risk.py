from __future__ import annotations

"""Risk scoring: how much a hypothesis / verification deserves attention.

Combines severity, source confidence, dynamic confirmation and exposure
(is there a concrete endpoint, is the function an entry point).
"""

from app.security.models import Severity, Source, Verdict, Verification, VulnHypothesis

_SEVERITY_WEIGHT = {
    Severity.critical: 10.0,
    Severity.high: 7.0,
    Severity.medium: 4.0,
    Severity.low: 2.0,
    Severity.info: 1.0,
}


def hypothesis_risk(h: VulnHypothesis) -> float:
    base = _SEVERITY_WEIGHT.get(h.severity, 4.0)
    score = base * (0.5 + 0.5 * h.confidence)
    if h.endpoint:
        score *= 1.15          # concrete, reachable surface
    if h.function:
        score *= 1.05
    if h.source == Source.llm_review:
        score *= 0.95          # slightly less trusted than a dedicated engine
    return round(min(score, 10.0), 2)


def verification_risk(v: Verification, h: VulnHypothesis | None = None) -> float:
    if v.verdict == Verdict.confirmed:
        base = _SEVERITY_WEIGHT.get(v.severity, 7.0)
        return round(min(10.0, base * (0.6 + 0.4 * v.confidence)), 2)
    if v.verdict == Verdict.uncertain:
        return round(min(6.0, _SEVERITY_WEIGHT.get(v.severity, 4.0) * 0.5), 2)
    return 0.0


def priority_bucket(score: float) -> str:
    if score >= 8.5:
        return "P0"
    if score >= 6.5:
        return "P1"
    if score >= 4.0:
        return "P2"
    return "P3"

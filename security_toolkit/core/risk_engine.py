"""Finding / risk engine.

Produces ``Finding`` objects with a consistent severity model and computes
aggregate Risk / Security / Confidence scores. Severity is supplied explicitly
by each module based on real evidence -- it is deliberately *not* derived from a
naive keyword match on response text.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from security_toolkit.core.models import (
    Finding,
    SEVERITY_ORDER,
    SEVERITY_WEIGHT,
    CONFIDENCE_LEVELS,
)


def make_finding(
    title: str,
    category: str,
    severity: str = "INFO",
    confidence: str = "MEDIUM",
    *,
    target: str = "",
    evidence: str = "",
    impact: str = "",
    recommendation: str = "",
    reference: str = "",
    case_id: str = "",
    module: str = "",
) -> Finding:
    """Factory that normalizes and validates a finding."""
    return Finding(
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        target=target,
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        reference=reference,
        case_id=case_id,
        module=module,
    )


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "INFO").upper())
    except ValueError:
        return 0


def _confidence_factor(confidence: str) -> float:
    return {"LOW": 0.5, "MEDIUM": 0.8, "HIGH": 1.0}.get((confidence or "MEDIUM").upper(), 0.8)


def score(findings: Iterable[Finding]) -> Dict[str, object]:
    """Compute aggregate scores and a severity histogram.

    Risk Score is 0-100 (higher = worse). Security Score is its complement.
    Confidence Score is the evidence-weighted mean confidence of findings.
    """
    findings = list(findings)
    histogram: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    weighted = 0.0
    confidence_sum = 0.0

    for finding in findings:
        sev = (finding.severity or "INFO").upper()
        histogram[sev] = histogram.get(sev, 0) + 1
        weighted += SEVERITY_WEIGHT.get(sev, 0) * _confidence_factor(finding.confidence)
        confidence_sum += _confidence_factor(finding.confidence)

    actionable = [f for f in findings if severity_rank(f.severity) >= 1]  # exclude INFO
    if actionable:
        # Normalize by a soft ceiling so a handful of criticals saturate the score.
        raw = weighted / (len(actionable) * SEVERITY_WEIGHT["CRITICAL"])
        # emphasize the single worst finding too
        worst = max((SEVERITY_WEIGHT.get(f.severity, 0) for f in actionable), default=0)
        risk = min(100.0, 100.0 * (0.6 * raw + 0.4 * worst / 10.0))
    else:
        risk = 0.0

    confidence_score = (confidence_sum / len(findings) * 100.0) if findings else 0.0

    return {
        "risk_score": round(risk, 1),
        "security_score": round(100.0 - risk, 1),
        "confidence_score": round(confidence_score, 1),
        "severity_histogram": histogram,
        "total_findings": len(findings),
        "actionable_findings": len(actionable),
    }


def worst_severity(findings: Iterable[Finding]) -> str:
    best = 0
    for finding in findings:
        best = max(best, severity_rank(finding.severity))
    return SEVERITY_ORDER[best]


__all__ = [
    "make_finding", "score", "severity_rank", "worst_severity",
    "SEVERITY_ORDER", "CONFIDENCE_LEVELS",
]

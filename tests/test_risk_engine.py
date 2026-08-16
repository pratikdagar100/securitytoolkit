from security_toolkit.core import risk_engine
from security_toolkit.core.models import Finding


def test_score_empty():
    s = risk_engine.score([])
    assert s["risk_score"] == 0.0
    assert s["total_findings"] == 0


def test_score_orders_and_counts():
    findings = [
        Finding("a", "WEB", "CRITICAL", "HIGH"),
        Finding("b", "WEB", "LOW", "MEDIUM"),
        Finding("c", "WEB", "INFO", "HIGH"),
    ]
    s = risk_engine.score(findings)
    assert s["severity_histogram"]["CRITICAL"] == 1
    assert s["actionable_findings"] == 2   # INFO excluded
    assert 0 < s["risk_score"] <= 100
    assert s["security_score"] == round(100 - s["risk_score"], 1)


def test_worst_severity():
    findings = [Finding("a", "X", "LOW"), Finding("b", "X", "HIGH")]
    assert risk_engine.worst_severity(findings) == "HIGH"


def test_make_finding_normalizes_bad_severity():
    f = risk_engine.make_finding("t", "C", severity="BOGUS", confidence="x")
    assert f.severity == "INFO"
    assert f.confidence == "MEDIUM"

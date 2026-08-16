from security_toolkit.reporting import build_report_data, Reporter


def _sample_case():
    case = {"case_id": "CASE-2026-001", "name": "Demo", "purpose": "test",
            "authorized_by": "CISO", "status": "ACTIVE", "created_at": "now",
            "created_by": "local", "notes": ""}
    targets = [{"value": "example.com", "target_type": "domain", "authorized": 1,
                "scope": "example.com"}]
    findings = [{"finding_id": "F-1", "category": "WEB_SECURITY",
                 "title": "Missing Content-Security-Policy", "severity": "MEDIUM",
                 "confidence": "HIGH", "target": "example.com", "evidence": "no CSP",
                 "recommendation": "add CSP", "timestamp": "now", "module": "web"}]
    events = [{"timestamp": "now", "category": "SCANNING", "severity": "LOW",
               "target": "1.2.3.4", "evidence": "many paths"}]
    evidence = [{"evidence_id": "EVD-1", "source": "module:web",
                 "description": "raw", "sha256": "a" * 64}]
    return case, targets, findings, events, evidence


def test_build_report_data_scores():
    data = build_report_data(*_sample_case())
    assert data["scores"]["total_findings"] == 1
    assert "WEB_SECURITY" in data["findings_by_category"]


def test_html_and_json_and_csv(tmp_path):
    data = build_report_data(*_sample_case())
    r = Reporter(data)
    html = r.to_html(tmp_path / "r.html")
    js = r.to_json(tmp_path / "r.json")
    csv = r.to_csv(tmp_path / "r.csv")
    assert "Missing Content-Security-Policy" in html.read_text(encoding="utf-8")
    assert js.read_text(encoding="utf-8").strip().startswith("{")
    assert "finding_id" in csv.read_text(encoding="utf-8")

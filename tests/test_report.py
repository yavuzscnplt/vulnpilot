from datetime import timedelta

from vulnpilot.models import Finding, ScanReport, Severity, Target, ToolResult, utcnow
from vulnpilot.report import to_html, to_json, to_markdown


def _sample_report() -> ScanReport:
    target = Target(url="https://x.test", hostname="x.test")
    now = utcnow()
    finding = Finding(
        title="Eksik HSTS",
        severity=Severity.MEDIUM,
        description="HSTS yok",
        tool="http_probe",
        target=target.url,
        evidence="no strict-transport-security",
        remediation="HSTS ekle",
        references=["https://owasp.org"],
    )
    result = ToolResult("http_probe", target.url, True, 0.2, findings=[finding])
    return ScanReport(
        target, now, now + timedelta(seconds=2), plan=["http_probe"],
        tool_results=[result], summary="Orta seviye risk.",
    )


def test_markdown_contains_finding_and_summary():
    md = to_markdown(_sample_report())
    assert "Eksik HSTS" in md
    assert "Yönetici Özeti" in md
    assert "HSTS ekle" in md


def test_html_is_self_contained_and_escaped():
    html = to_html(_sample_report())
    assert html.startswith("<!doctype html>")
    assert "Eksik HSTS" in html
    assert "<style>" in html  # inline CSS, no external assets


def test_json_roundtrips():
    import json

    data = json.loads(to_json(_sample_report()))
    assert data["findings"][0]["title"] == "Eksik HSTS"
    assert data["severity_counts"]["Medium"] == 1

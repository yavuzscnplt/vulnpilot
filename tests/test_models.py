from datetime import timedelta

from vulnpilot.models import Finding, ScanReport, Severity, Target, ToolResult, utcnow


def test_severity_parse_and_order():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("BOGUS") is Severity.INFO
    assert Severity.CRITICAL > Severity.LOW


def test_report_sorts_findings_by_severity_desc():
    target = Target(url="https://x.test", hostname="x.test")
    start = utcnow()
    low = Finding("low", Severity.LOW, "", "t", target.url)
    crit = Finding("crit", Severity.CRITICAL, "", "t", target.url)
    result = ToolResult("t", target.url, True, 0.1, findings=[low, crit])
    report = ScanReport(target, start, start + timedelta(seconds=1), tool_results=[result])

    assert [f.severity for f in report.findings] == [Severity.CRITICAL, Severity.LOW]
    assert report.severity_counts()["Critical"] == 1
    assert report.duration_s == 1.0


def test_report_to_dict_is_json_safe():
    target = Target(url="https://x.test", hostname="x.test")
    now = utcnow()
    report = ScanReport(target, now, now)
    data = report.to_dict()
    assert data["target"] == "https://x.test"
    assert "severity_counts" in data

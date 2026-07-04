"""End-to-end orchestrator test using a fake tool + offline brain (no network)."""


from vulnpilot.config import Settings
from vulnpilot.llm import Brain
from vulnpilot.models import Finding, Severity, Target, ToolResult
from vulnpilot.orchestrator import Orchestrator
from vulnpilot.tools.base import Tool, register


@register
class _FakeTool(Tool):
    name = "fake_tool"
    description = "Test amaçlı sahte araç."
    binary = ""

    def run(self, target: Target) -> ToolResult:
        f = Finding(
            title="Sahte bulgu",
            severity=Severity.HIGH,
            description="test",
            tool=self.name,
            target=target.url,
        )
        return ToolResult(self.name, target.url, True, 0.01, findings=[f])


def test_scan_runs_available_tools_and_produces_report():
    settings = Settings()  # no API key -> offline brain
    orch = Orchestrator(settings, brain=Brain(settings))
    target = Target(url="https://demo.test", hostname="demo.test")

    events: list[tuple[str, str]] = []
    report = orch.scan(target, on_event=lambda e, d: events.append((e, d)))

    # offline plan runs every available tool, including our fake one
    assert "fake_tool" in report.plan
    titles = [f.title for f in report.findings]
    assert "Sahte bulgu" in titles
    assert report.summary  # fallback summary is non-empty
    assert any(e[0] == "run_done" for e in events)


def test_offline_brain_summary_mentions_counts():
    settings = Settings()
    brain = Brain(settings)
    assert not brain.online
    target = Target(url="https://demo.test", hostname="demo.test")
    findings = [
        Finding("a", Severity.CRITICAL, "", "t", target.url),
        Finding("b", Severity.LOW, "", "t", target.url),
    ]
    summary = brain.summarize(target, findings)
    assert "2 bulgu" in summary

"""The orchestrator — VulnPilot's control loop.

    plan (AI picks tools)  ->  execute (run each tool)  ->  interpret (AI triages)

It ties together the scope guard, the tool registry and the Claude "brain" into
a single scan() call that returns a ScanReport.
"""

from __future__ import annotations

from collections.abc import Callable

from .config import Settings
from .llm import Brain
from .models import ScanReport, Target, ToolResult, utcnow
from .tools import registry
from .tools.base import Tool

# Optional progress callback: (event, detail) -> None
Reporter = Callable[[str, str], None]


def _noop(_event: str, _detail: str) -> None:
    pass


class Orchestrator:
    def __init__(self, settings: Settings, brain: Brain | None = None) -> None:
        self.settings = settings
        self.brain = brain or Brain(settings)
        self._tools: dict[str, Tool] = {
            name: cls(settings) for name, cls in registry().items()
        }

    def available_tools(self) -> list[Tool]:
        return [t for t in self._tools.values() if t.is_available()]

    def all_tools(self) -> list[Tool]:
        return list(self._tools.values())

    def scan(self, target: Target, on_event: Reporter = _noop) -> ScanReport:
        started = utcnow()

        available = self.available_tools()
        if not available:
            raise RuntimeError("Kullanılabilir hiçbir araç yok.")

        # 1) PLAN --------------------------------------------------------
        catalog = [{"name": t.name, "description": t.description} for t in available]
        on_event("plan", "AI araç planı çıkarıyor" if self.brain.online else "Varsayılan plan")
        plan = self.brain.plan(target, catalog)
        chosen = plan["tools"]
        on_event("plan_done", ", ".join(chosen))

        # 2) EXECUTE -----------------------------------------------------
        results: list[ToolResult] = []
        for name in chosen:
            tool = self._tools.get(name)
            if tool is None or not tool.is_available():
                continue
            on_event("run", name)
            result = tool.run(target)
            on_event("run_done", f"{name}: {len(result.findings)} bulgu")
            results.append(result)

        # 3) INTERPRET ---------------------------------------------------
        all_findings = [f for r in results for f in r.findings]
        on_event("summary", "AI özet/triaj yazıyor" if self.brain.online else "Özet üretiliyor")
        summary = self.brain.summarize(target, all_findings)

        return ScanReport(
            target=target,
            started_at=started,
            finished_at=utcnow(),
            plan=chosen,
            plan_rationale=plan.get("rationale", ""),
            tool_results=results,
            summary=summary,
        )

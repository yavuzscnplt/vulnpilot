"""Core data models shared across VulnPilot.

Everything the orchestrator, tools and reporter pass around is defined here so
there is a single, typed source of truth. Plain dataclasses are used on purpose:
zero runtime dependencies, trivial to serialise to JSON for reports.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so findings can be sorted most-critical first."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "#3b82f6",
            Severity.LOW: "#22c55e",
            Severity.MEDIUM: "#eab308",
            Severity.HIGH: "#f97316",
            Severity.CRITICAL: "#ef4444",
        }[self]

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            return cls.INFO


@dataclass(slots=True)
class Target:
    """A single authorized scan target."""

    url: str
    hostname: str
    scheme: str = "https"
    authorized: bool = False
    notes: str = ""


@dataclass(slots=True)
class Finding:
    """A single security observation produced by a tool or the AI."""

    title: str
    severity: Severity
    description: str
    tool: str
    target: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        return data


@dataclass(slots=True)
class ToolResult:
    """Raw + parsed output from one tool run."""

    tool: str
    target: str
    ok: bool
    duration_s: float
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "ok": self.ok,
            "duration_s": round(self.duration_s, 2),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass(slots=True)
class ScanReport:
    """The full result of a scan, ready to be rendered."""

    target: Target
    started_at: datetime
    finished_at: datetime
    plan: list[str] = field(default_factory=list)
    plan_rationale: str = ""
    tool_results: list[ToolResult] = field(default_factory=list)
    summary: str = ""

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for result in self.tool_results:
            out.extend(result.findings)
        return sorted(out, key=lambda f: f.severity, reverse=True)

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.url,
            "hostname": self.target.hostname,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_s": round(self.duration_s, 2),
            "plan": self.plan,
            "plan_rationale": self.plan_rationale,
            "summary": self.summary,
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "tool_results": [r.to_dict() for r in self.tool_results],
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

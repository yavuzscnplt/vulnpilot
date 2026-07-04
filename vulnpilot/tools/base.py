"""Tool plugin contract + registry.

Every capability VulnPilot has is a Tool: a small, self-describing unit that
knows whether it is available on this machine and how to run against a target.
New tools register themselves via @register, so the orchestrator and CLI can
discover them without hard-coded lists.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod

from ..config import Settings
from ..models import Target, ToolResult, utcnow

_REGISTRY: dict[str, type[Tool]] = {}


def register(cls: type[Tool]) -> type[Tool]:
    _REGISTRY[cls.name] = cls
    return cls


def registry() -> dict[str, type[Tool]]:
    return dict(_REGISTRY)


class Tool(ABC):
    """Base class for all scanning capabilities."""

    #: unique, cli-friendly identifier (e.g. "nuclei")
    name: str = ""
    #: one-line description shown to the AI planner and in `vulnpilot tools`
    description: str = ""
    #: name of the external binary this tool wraps, or "" for pure-python tools
    binary: str = ""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def is_available(self) -> bool:
        """Builtin tools are always available; wrappers need their binary."""
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    @abstractmethod
    def run(self, target: Target) -> ToolResult:  # pragma: no cover - interface
        ...

    # -- helpers shared by external-binary wrappers ------------------- #
    def _exec(self, args: list[str]) -> tuple[bool, str, str]:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.settings.tool_timeout_s,
            )
            return proc.returncode == 0, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return False, "", "zaman aşımı"
        except FileNotFoundError:
            return False, "", f"{self.binary} bulunamadı"

    def _timed(self):
        return _Timer()


class _Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.duration = time.perf_counter() - self.start


def blank_result(tool: str, target: Target, error: str) -> ToolResult:
    return ToolResult(
        tool=tool, target=target.url, ok=False, duration_s=0.0, error=error
    )


def _now():  # re-exported for tools that timestamp findings
    return utcnow()

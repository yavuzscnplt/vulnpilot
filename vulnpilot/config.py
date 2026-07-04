"""Runtime configuration, loaded from environment (and optional .env)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so we don't pull in a dependency for five lines."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


@dataclass(slots=True)
class Settings:
    """All tunables in one place. Env vars win over defaults."""

    anthropic_api_key: str = ""
    model: str = "claude-sonnet-5"
    max_tokens: int = 2048
    request_timeout_s: float = 15.0
    tool_timeout_s: float = 180.0
    output_dir: Path = Path("reports")
    user_agent: str = "VulnPilot/0.1 (+authorized-security-testing)"

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)

    @classmethod
    def load(cls, dotenv: Path | None = None) -> Settings:
        _load_dotenv(dotenv or Path(".env"))
        # NB: with slots=True, class-level attributes are slot descriptors, not
        # the default values — so read defaults from a fresh instance.
        d = cls()
        return cls(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            model=os.getenv("VULNPILOT_MODEL", d.model),
            max_tokens=int(os.getenv("VULNPILOT_MAX_TOKENS", d.max_tokens)),
            request_timeout_s=float(
                os.getenv("VULNPILOT_HTTP_TIMEOUT", d.request_timeout_s)
            ),
            tool_timeout_s=float(
                os.getenv("VULNPILOT_TOOL_TIMEOUT", d.tool_timeout_s)
            ),
            output_dir=Path(os.getenv("VULNPILOT_OUTPUT_DIR", "reports")),
            user_agent=os.getenv("VULNPILOT_USER_AGENT", d.user_agent),
        )

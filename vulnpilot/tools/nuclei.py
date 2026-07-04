"""Wrapper around ProjectDiscovery's `nuclei` — known-vulnerability scanner.

nuclei runs a large community template library against a target. We invoke it
in JSONL mode and map each hit onto a VulnPilot Finding. If nuclei is not
installed the tool simply reports itself unavailable and the orchestrator
skips it.
"""

from __future__ import annotations

import json
import time

from ..models import Finding, Severity, Target, ToolResult
from .base import Tool, register


@register
class Nuclei(Tool):
    name = "nuclei"
    description = "Bilinen zafiyet/CVE ve yanlış yapılandırma taraması (ProjectDiscovery template'leri)."
    binary = "nuclei"

    def run(self, target: Target) -> ToolResult:
        start = time.perf_counter()
        # -silent + -jsonl: makine-okunur çıktı; -duc: güncelleme kontrolünü atla
        ok, stdout, stderr = self._exec(
            [self.binary, "-u", target.url, "-jsonl", "-silent", "-duc"]
        )
        duration = time.perf_counter() - start

        findings: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._to_finding(hit, target))

        # nuclei bulgu bulamayınca da returncode 0 döner; stderr'i sadece
        # gerçekten çalışmadıysa hata say.
        failed = not ok and not stdout
        return ToolResult(
            tool=self.name,
            target=target.url,
            ok=not failed,
            duration_s=duration,
            findings=findings,
            raw_output=stdout[:6000],
            error=stderr.strip() if failed else "",
        )

    @staticmethod
    def _to_finding(hit: dict, target: Target) -> Finding:
        info = hit.get("info", {})
        sev = Severity.parse(info.get("severity", "info"))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        return Finding(
            title=info.get("name", hit.get("template-id", "nuclei bulgusu")),
            severity=sev,
            description=info.get("description", "") or "nuclei template eşleşmesi.",
            tool="nuclei",
            target=hit.get("matched-at", target.url),
            evidence=hit.get("matched-at", "") or hit.get("template-id", ""),
            remediation=info.get("remediation", ""),
            references=list(refs)[:5],
        )

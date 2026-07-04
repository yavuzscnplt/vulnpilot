"""Wrapper around ProjectDiscovery's `subfinder` — passive subdomain discovery.

Enumerates subdomains of the target's registrable domain from passive sources
(no brute force). Each discovered host becomes an INFO finding so the operator
can widen scope deliberately. Unavailable if the binary is missing.
"""

from __future__ import annotations

import time

from ..models import Finding, Severity, Target, ToolResult
from .base import Tool, register


@register
class Subfinder(Tool):
    name = "subfinder"
    description = "Pasif alt alan adı keşfi (saldırı yüzeyini haritalar)."
    binary = "subfinder"

    def run(self, target: Target) -> ToolResult:
        start = time.perf_counter()
        ok, stdout, stderr = self._exec(
            [self.binary, "-d", target.hostname, "-silent"]
        )
        duration = time.perf_counter() - start

        subs = sorted({line.strip() for line in stdout.splitlines() if line.strip()})
        findings: list[Finding] = []
        if subs:
            preview = "\n".join(subs[:50])
            findings.append(
                Finding(
                    title=f"{len(subs)} alt alan adı keşfedildi",
                    severity=Severity.INFO,
                    description=(
                        "Pasif kaynaklardan bulunan alt alan adları saldırı yüzeyini "
                        "genişletir. Her biri ayrıca değerlendirilmeli."
                    ),
                    tool=self.name,
                    target=target.hostname,
                    evidence=preview + ("\n…" if len(subs) > 50 else ""),
                    remediation="Kullanılmayan/eski alt alan adlarını kaldır; her aktif olanı ayrıca test et.",
                )
            )

        failed = not ok and not stdout
        return ToolResult(
            tool=self.name,
            target=target.hostname,
            ok=not failed,
            duration_s=duration,
            findings=findings,
            raw_output=stdout[:6000],
            error=stderr.strip() if failed else "",
        )

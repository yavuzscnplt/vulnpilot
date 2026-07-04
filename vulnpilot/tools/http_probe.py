"""Builtin HTTP probe — the tool that always works, no external binary needed.

Fetches the target once and derives real findings from the response:
  * missing / misconfigured security headers (HSTS, CSP, X-Frame-Options, ...)
  * insecure cookie flags (missing Secure / HttpOnly)
  * server / technology disclosure via banner headers

This guarantees VulnPilot produces meaningful output on a fresh clone even if
nuclei/httpx/subfinder are not installed.
"""

from __future__ import annotations

import time

from ..models import Finding, Severity, Target, ToolResult
from .base import Tool, register

# header -> (severity, human explanation, remediation)
_SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "HSTS başlığı yok; tarayıcı HTTPS'i zorlamıyor, SSL-stripping riski.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains ekle.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "CSP başlığı yok; XSS ve veri sızıntısına karşı önemli bir katman eksik.",
        "İçeriğe uygun bir Content-Security-Policy tanımla.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options yok; clickjacking'e karşı korumasız olabilir.",
        "X-Frame-Options: DENY (veya CSP frame-ancestors) ekle.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options yok; MIME-sniffing mümkün.",
        "X-Content-Type-Options: nosniff ekle.",
    ),
    "referrer-policy": (
        Severity.INFO,
        "Referrer-Policy yok; gezinme bilgisi üçüncü taraflara sızabilir.",
        "Referrer-Policy: strict-origin-when-cross-origin ekle.",
    ),
}

_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@register
class HttpProbe(Tool):
    name = "http_probe"
    description = "Güvenlik başlıkları, çerez bayrakları ve teknoloji ifşası kontrolü (dahili)."
    binary = ""

    def run(self, target: Target) -> ToolResult:
        start = time.perf_counter()
        try:
            import httpx
        except ImportError:
            return ToolResult(
                tool=self.name,
                target=target.url,
                ok=False,
                duration_s=0.0,
                error="httpx paketi kurulu değil (pip install httpx).",
            )

        findings: list[Finding] = []
        raw = ""
        try:
            with httpx.Client(
                follow_redirects=True,
                timeout=self.settings.request_timeout_s,
                headers={"User-Agent": self.settings.user_agent},
                verify=True,
            ) as client:
                resp = client.get(target.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw = f"HTTP {resp.status_code}\n" + "\n".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )

            findings.extend(self._check_headers(headers, target))
            findings.extend(self._check_cookies(resp, target))
            findings.extend(self._check_disclosure(headers, target))
        except Exception as exc:  # noqa: BLE001 - report any transport error
            return ToolResult(
                tool=self.name,
                target=target.url,
                ok=False,
                duration_s=time.perf_counter() - start,
                error=f"İstek başarısız: {exc}",
            )

        return ToolResult(
            tool=self.name,
            target=target.url,
            ok=True,
            duration_s=time.perf_counter() - start,
            findings=findings,
            raw_output=raw[:4000],
        )

    def _check_headers(self, headers: dict[str, str], target: Target) -> list[Finding]:
        out: list[Finding] = []
        for name, (sev, desc, fix) in _SECURITY_HEADERS.items():
            if name not in headers:
                out.append(
                    Finding(
                        title=f"Eksik güvenlik başlığı: {name}",
                        severity=sev,
                        description=desc,
                        tool=self.name,
                        target=target.url,
                        evidence=f"Yanıtta {name} başlığı yok.",
                        remediation=fix,
                        references=[
                            "https://owasp.org/www-project-secure-headers/"
                        ],
                    )
                )
        return out

    def _check_cookies(self, resp, target: Target) -> list[Finding]:
        out: list[Finding] = []
        for cookie in resp.cookies.jar:
            issues = []
            if not cookie.secure:
                issues.append("Secure")
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(
                cookie, "_rest", {}
            ).get("HttpOnly"):
                issues.append("HttpOnly")
            if issues:
                out.append(
                    Finding(
                        title=f"Güvensiz çerez: {cookie.name}",
                        severity=Severity.MEDIUM,
                        description=f"Çerezde eksik bayrak(lar): {', '.join(issues)}.",
                        tool=self.name,
                        target=target.url,
                        evidence=f"Set-Cookie: {cookie.name} ({', '.join(issues)} yok)",
                        remediation="Oturum çerezlerine Secure ve HttpOnly bayraklarını ekle.",
                    )
                )
        return out

    def _check_disclosure(self, headers: dict[str, str], target: Target) -> list[Finding]:
        out: list[Finding] = []
        for name in _DISCLOSURE_HEADERS:
            if name in headers and headers[name].strip():
                out.append(
                    Finding(
                        title=f"Teknoloji ifşası: {name}",
                        severity=Severity.INFO,
                        description="Sunucu, saldırgana yardımcı olabilecek sürüm/teknoloji bilgisi sızdırıyor.",
                        tool=self.name,
                        target=target.url,
                        evidence=f"{name}: {headers[name]}",
                        remediation=f"{name} başlığını kaldır veya sürüm bilgisini gizle.",
                    )
                )
        return out

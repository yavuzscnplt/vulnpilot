"""Builtin TLS/certificate probe — no external binary needed.

Opens a TLS connection to the target host and inspects the negotiated
protocol version and the leaf certificate (expiry, hostname match). Produces
real findings for expired certs, near-expiry, and legacy TLS versions.
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

from ..models import Finding, Severity, Target, ToolResult
from .base import Tool, register

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


@register
class TlsProbe(Tool):
    name = "tls_probe"
    description = "TLS sürümü ve sertifika geçerliliği/son kullanma kontrolü (dahili)."
    binary = ""

    def is_available(self) -> bool:
        return True

    def run(self, target: Target) -> ToolResult:
        start = time.perf_counter()
        if target.scheme != "https":
            return ToolResult(
                tool=self.name,
                target=target.url,
                ok=True,
                duration_s=time.perf_counter() - start,
                findings=[
                    Finding(
                        title="Hedef HTTPS kullanmıyor",
                        severity=Severity.HIGH,
                        description="Trafik şifrelenmiyor; kimlik bilgileri ve oturum verisi açık taşınır.",
                        tool=self.name,
                        target=target.url,
                        evidence=f"Şema: {target.scheme}",
                        remediation="Tüm trafiği HTTPS'e taşı ve HTTP'yi HTTPS'e yönlendir.",
                    )
                ],
            )

        findings: list[Finding] = []
        raw = ""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (target.hostname, 443), timeout=self.settings.request_timeout_s
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=target.hostname) as ssock:
                    proto = ssock.version() or "?"
                    cert = ssock.getpeercert()
            raw = f"protocol={proto}\ncert={cert}"
            findings.extend(self._check_protocol(proto, target))
            findings.extend(self._check_expiry(cert, target))
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                Finding(
                    title="Sertifika doğrulaması başarısız",
                    severity=Severity.HIGH,
                    description="Sunucu sertifikası güvenilir zincirle doğrulanamadı.",
                    tool=self.name,
                    target=target.url,
                    evidence=str(exc),
                    remediation="Geçerli, güvenilir bir CA'dan sertifika kur; zinciri tamamla.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(
                tool=self.name,
                target=target.url,
                ok=False,
                duration_s=time.perf_counter() - start,
                error=f"TLS bağlantısı kurulamadı: {exc}",
            )

        return ToolResult(
            tool=self.name,
            target=target.url,
            ok=True,
            duration_s=time.perf_counter() - start,
            findings=findings,
            raw_output=raw[:2000],
        )

    def _check_protocol(self, proto: str, target: Target) -> list[Finding]:
        if proto in _WEAK_PROTOCOLS:
            return [
                Finding(
                    title=f"Zayıf TLS sürümü: {proto}",
                    severity=Severity.MEDIUM,
                    description="Eski TLS/SSL sürümleri bilinen kriptografik zafiyetler içerir.",
                    tool=self.name,
                    target=target.url,
                    evidence=f"Anlaşılan protokol: {proto}",
                    remediation="En az TLS 1.2 (tercihen 1.3) zorunlu kıl, eskileri kapat.",
                )
            ]
        return []

    def _check_expiry(self, cert: dict | None, target: Target) -> list[Finding]:
        if not cert or "notAfter" not in cert:
            return []
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days = (expires - datetime.now(timezone.utc)).days
        if days < 0:
            sev, title = Severity.HIGH, "Sertifika süresi dolmuş"
        elif days <= 14:
            sev, title = Severity.MEDIUM, f"Sertifika {days} gün içinde dolacak"
        else:
            return []
        return [
            Finding(
                title=title,
                severity=sev,
                description="Süresi dolan/dolmak üzere olan sertifika tarayıcı uyarısına ve kesintiye yol açar.",
                tool=self.name,
                target=target.url,
                evidence=f"notAfter: {cert['notAfter']}",
                remediation="Sertifikayı yenile; otomatik yenileme (ör. ACME) kur.",
            )
        ]

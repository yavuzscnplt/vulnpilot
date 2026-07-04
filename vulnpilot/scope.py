"""Authorization & scope guard.

Running a scanner against a host you are not allowed to test can be illegal.
VulnPilot refuses to start until the operator confirms authorization, and it
normalises/validates the target before any traffic is sent. This module is
deliberately conservative — it is the ethical backbone of the tool.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .models import Target


class ScopeError(Exception):
    """Raised when a target cannot be scanned safely or legally."""


def normalize_target(raw: str) -> Target:
    """Turn user input into a validated Target.

    Accepts bare hostnames ("example.com") or full URLs
    ("https://example.com/app"). Defaults to https.
    """
    raw = raw.strip()
    if not raw:
        raise ScopeError("Boş hedef verildi.")

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"Desteklenmeyen şema: {parsed.scheme!r} (http/https bekleniyor).")
    if not parsed.hostname:
        raise ScopeError(f"Hedeften host adı çıkarılamadı: {raw!r}")

    return Target(
        url=raw.rstrip("/"),
        hostname=parsed.hostname,
        scheme=parsed.scheme,
    )


def resolve(hostname: str) -> str | None:
    """Best-effort DNS resolution; returns None if it cannot resolve."""
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def is_private(hostname: str) -> bool:
    """True for localhost / RFC1918 / loopback targets (safe to self-test)."""
    if hostname in ("localhost",):
        return True
    ip = resolve(hostname)
    if ip is None:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def authorize(target: Target, *, assume_yes: bool = False) -> Target:
    """Interactively (or non-interactively) confirm authorization.

    Private/loopback targets are treated as self-testing and only require a
    light confirmation. Public targets always require an explicit yes.
    """
    if assume_yes:
        target.authorized = True
        target.notes = "Authorization asserted via --yes flag."
        return target

    scope_kind = "kendi/lokal sistem" if is_private(target.hostname) else "DIŞ hedef"
    print(
        f"\n[!] Tarama hedefi: {target.url}  ({scope_kind})\n"
        "    Yalnızca sahibi olduğun ya da yazılı izinli olduğun sistemleri test et.\n"
        "    İzinsiz tarama birçok ülkede suçtur.\n"
    )
    answer = input("    Bu hedefi test etme yetkin olduğunu onaylıyor musun? [e/H] ").strip().lower()
    if answer not in ("e", "evet", "y", "yes"):
        raise ScopeError("Yetki onaylanmadı — tarama iptal edildi.")

    target.authorized = True
    return target

"""Thin wrapper around the Claude API used as the orchestrator's "brain".

Two responsibilities:
  1. plan()      — pick which tools to run against a target and why.
  2. summarize() — turn raw findings into an executive summary + triage.

If no API key is configured (or the SDK is missing) the wrapper degrades
gracefully to deterministic heuristics, so VulnPilot still runs end-to-end
without any AI. That keeps the demo path alive for anyone cloning the repo.
"""

from __future__ import annotations

import json
from typing import Any

from .config import Settings
from .models import Finding, Target

_PLANNER_SYSTEM = """Sen VulnPilot'un planlama motorusun; yetkili (authorized) web \
uygulaması güvenlik testleri için araç seçimi yaparsın. Sana bir hedef ve kullanılabilir \
araçların listesi verilir. Yalnızca pasif/güvenli keşif ve bilinen-zafiyet taraması \
öner — yıkıcı, DoS veya kaba-kuvvet eylemi ÖNERME. Sadece geçerli JSON döndür."""

_SUMMARY_SYSTEM = """Sen kıdemli bir sızma testi uzmanısın. Sana bir hedefe ait ham \
bulgular verilir. Yönetici özeti (risk seviyesi + iş etkisi) yaz, ardından bulguları \
önem sırasına göre triç et ve somut düzeltme önerileri ver. Türkçe, net, abartısız."""


class Brain:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client: Any | None = None
        if settings.ai_enabled:
            try:  # optional dependency — only imported when a key exists
                import anthropic

                self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            except Exception:  # pragma: no cover - defensive
                self._client = None

    @property
    def online(self) -> bool:
        return self._client is not None

    # ------------------------------------------------------------------ #
    def plan(self, target: Target, available_tools: list[dict[str, str]]) -> dict[str, Any]:
        """Return {"tools": [...], "rationale": "..."}."""
        if not self.online:
            return self._fallback_plan(available_tools)

        prompt = (
            f"Hedef: {target.url}\n"
            f"Host: {target.hostname}\n\n"
            "Kullanılabilir araçlar:\n"
            + "\n".join(f"- {t['name']}: {t['description']}" for t in available_tools)
            + '\n\nJSON şeması: {"tools": ["arac_adi", ...], "rationale": "kısa gerekçe"}'
        )
        try:
            text = self._complete(_PLANNER_SYSTEM, prompt)
            data = _extract_json(text)
            names = {t["name"] for t in available_tools}
            chosen = [n for n in data.get("tools", []) if n in names]
            if not chosen:
                return self._fallback_plan(available_tools)
            return {"tools": chosen, "rationale": data.get("rationale", "")}
        except Exception:
            return self._fallback_plan(available_tools)

    def summarize(self, target: Target, findings: list[Finding]) -> str:
        if not findings:
            base = "Otomatik kontrollerde belirgin bir zafiyet bulunmadı. "
        else:
            base = ""
        if not self.online:
            return base + self._fallback_summary(findings)

        payload = json.dumps(
            [
                {
                    "title": f.title,
                    "severity": f.severity.label,
                    "tool": f.tool,
                    "evidence": f.evidence[:400],
                }
                for f in findings
            ],
            ensure_ascii=False,
            indent=2,
        )
        prompt = f"Hedef: {target.url}\n\nBulgular:\n{payload}"
        try:
            return self._complete(_SUMMARY_SYSTEM, prompt)
        except Exception:
            return base + self._fallback_summary(findings)

    # ------------------------------------------------------------------ #
    def _complete(self, system: str, prompt: str) -> str:
        message = self._client.messages.create(  # type: ignore[union-attr]
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        )

    @staticmethod
    def _fallback_plan(available_tools: list[dict[str, str]]) -> dict[str, Any]:
        return {
            "tools": [t["name"] for t in available_tools],
            "rationale": "AI kapalı — kullanılabilir tüm güvenli araçlar sırayla çalıştırılıyor.",
        }

    @staticmethod
    def _fallback_summary(findings: list[Finding]) -> str:
        if not findings:
            return "Ek olarak manuel doğrulama önerilir."
        top = max(findings, key=lambda f: f.severity)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
        breakdown = ", ".join(f"{v} {k}" for k, v in counts.items())
        return (
            f"Toplam {len(findings)} bulgu ({breakdown}). "
            f"En yüksek önem: {top.severity.label} — {top.title}. "
            "Önce yüksek/kritik bulgular giderilmeli."
        )


def _extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Yanıtta JSON bulunamadı")
    return json.loads(text[start : end + 1])

"""Report renderers: JSON, Markdown and a self-contained HTML page.

The HTML report inlines all CSS so it can be opened or shared as a single file
with no assets — handy for attaching to an engagement deliverable.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanReport, Severity


def to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def to_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"# VulnPilot Raporu — {report.target.url}\n")
    lines.append(f"- **Tarih:** {report.finished_at:%Y-%m-%d %H:%M UTC}")
    lines.append(f"- **Süre:** {report.duration_s:.1f} sn")
    lines.append(f"- **Çalıştırılan araçlar:** {', '.join(report.plan) or '—'}")
    counts = ", ".join(f"{k}: {v}" for k, v in report.severity_counts().items() if v)
    lines.append(f"- **Bulgular:** {counts or 'yok'}\n")

    lines.append("## Yönetici Özeti\n")
    lines.append(report.summary or "_Özet yok._")
    lines.append("")

    lines.append("## Bulgular\n")
    if not report.findings:
        lines.append("_Otomatik kontrollerde bulgu yok._\n")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. [{f.severity.label}] {f.title}")
        lines.append(f"- **Araç:** {f.tool}")
        lines.append(f"- **Hedef:** {f.target}")
        lines.append(f"- **Açıklama:** {f.description}")
        if f.evidence:
            lines.append(f"- **Kanıt:**\n\n  ```\n  {f.evidence}\n  ```")
        if f.remediation:
            lines.append(f"- **Çözüm:** {f.remediation}")
        if f.references:
            lines.append("- **Kaynaklar:** " + ", ".join(f.references))
        lines.append("")

    lines.append("---")
    lines.append("_VulnPilot ile üretildi. Yalnızca yetkili test içindir._")
    return "\n".join(lines)


def to_html(report: ScanReport) -> str:
    def esc(text: str) -> str:
        return html.escape(str(text))

    chips = "".join(
        f'<span class="chip" style="--c:{Severity.parse(k).color}">{esc(k)}: {v}</span>'
        for k, v in report.severity_counts().items()
        if v
    ) or '<span class="chip" style="--c:#22c55e">Bulgu yok</span>'

    finding_cards = []
    for f in report.findings:
        refs = (
            "<div class='refs'>"
            + " · ".join(f'<a href="{esc(r)}">{esc(r)}</a>' for r in f.references)
            + "</div>"
            if f.references
            else ""
        )
        evidence = (
            f"<pre>{esc(f.evidence)}</pre>" if f.evidence else ""
        )
        remediation = (
            f"<p class='fix'><strong>Çözüm:</strong> {esc(f.remediation)}</p>"
            if f.remediation
            else ""
        )
        finding_cards.append(
            f"""
        <article class="finding" style="--c:{f.severity.color}">
          <header>
            <span class="sev">{esc(f.severity.label)}</span>
            <h3>{esc(f.title)}</h3>
            <span class="tool">{esc(f.tool)}</span>
          </header>
          <p class="tgt">{esc(f.target)}</p>
          <p>{esc(f.description)}</p>
          {evidence}
          {remediation}
          {refs}
        </article>"""
        )

    findings_html = "".join(finding_cards) or "<p class='empty'>Otomatik kontrollerde bulgu yok. 🎉</p>"
    summary_html = esc(report.summary).replace("\n", "<br>")

    return f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnPilot — {esc(report.target.hostname)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    margin: 0; background: #0f172a; color: #e2e8f0; line-height: 1.55; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  header.top {{ border-bottom: 1px solid #1e293b; padding-bottom: 1.25rem; margin-bottom: 1.5rem; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
  .muted {{ color: #94a3b8; font-size: .9rem; }}
  .chips {{ display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }}
  .chip {{ background: color-mix(in srgb, var(--c) 20%, transparent);
    border: 1px solid var(--c); color: #fff; padding: .25rem .6rem;
    border-radius: 999px; font-size: .8rem; font-weight: 600; }}
  section {{ margin-top: 2rem; }}
  h2 {{ font-size: 1.1rem; border-left: 3px solid #38bdf8; padding-left: .6rem; }}
  .summary {{ background: #1e293b; border-radius: 10px; padding: 1rem 1.25rem; }}
  .finding {{ background: #1e293b; border-left: 4px solid var(--c);
    border-radius: 8px; padding: 1rem 1.25rem; margin: .85rem 0; }}
  .finding header {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }}
  .finding h3 {{ font-size: 1rem; margin: 0; flex: 1; }}
  .sev {{ background: var(--c); color: #0f172a; font-weight: 700; font-size: .7rem;
    padding: .15rem .5rem; border-radius: 4px; text-transform: uppercase; }}
  .tool {{ color: #94a3b8; font-size: .75rem; font-family: ui-monospace, monospace; }}
  .tgt {{ color: #7dd3fc; font-size: .8rem; font-family: ui-monospace, monospace;
    margin: .3rem 0; word-break: break-all; }}
  pre {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px;
    padding: .6rem .8rem; overflow-x: auto; font-size: .8rem; }}
  .fix {{ color: #86efac; font-size: .9rem; }}
  .refs a {{ color: #7dd3fc; font-size: .78rem; }}
  .empty {{ color: #86efac; }}
  footer {{ margin-top: 3rem; color: #64748b; font-size: .8rem; text-align: center; }}
</style></head>
<body><div class="wrap">
  <header class="top">
    <h1>🛡️ VulnPilot Güvenlik Raporu</h1>
    <div class="muted">{esc(report.target.url)} · {report.finished_at:%Y-%m-%d %H:%M UTC}
      · {report.duration_s:.1f} sn</div>
    <div class="chips">{chips}</div>
    <div class="muted">Çalıştırılan araçlar: {esc(', '.join(report.plan) or '—')}</div>
  </header>
  <section><h2>Yönetici Özeti</h2><div class="summary">{summary_html or 'Özet yok.'}</div></section>
  <section><h2>Bulgular ({len(report.findings)})</h2>{findings_html}</section>
  <footer>VulnPilot v0.1 ile üretildi · Yalnızca yetkili güvenlik testi içindir.</footer>
</div></body></html>"""


def write_all(report: ScanReport, out_dir: Path, stem: str) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / f"{stem}.json",
        "md": out_dir / f"{stem}.md",
        "html": out_dir / f"{stem}.html",
    }
    paths["json"].write_text(to_json(report), encoding="utf-8")
    paths["md"].write_text(to_markdown(report), encoding="utf-8")
    paths["html"].write_text(to_html(report), encoding="utf-8")
    return paths

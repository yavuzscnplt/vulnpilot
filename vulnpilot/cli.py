"""VulnPilot command line interface."""

from __future__ import annotations

import sys
from pathlib import Path

# Windows konsolları sık sık cp1254/cp850 kod sayfasındadır ve Unicode
# glyph'leri (✓, 🧠 …) encode edemez. Çıktıyı UTF-8'e sabitleyerek her
# platformda tutarlı render sağlarız.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # pragma: no cover - stream may not support reconfigure
        pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import Settings
from .llm import Brain
from .models import ScanReport
from .orchestrator import Orchestrator
from .report import write_all
from .scope import ScopeError, authorize, is_private, normalize_target

app = typer.Typer(
    add_completion=False,
    help="🛡️ VulnPilot — AI-orkestralı web uygulaması güvenlik tarayıcısı.",
)
console = Console()


def _banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]VulnPilot[/] [dim]v" + __version__ + "[/]\n"
            "[dim]AI-orkestralı web güvenlik tarayıcısı[/]",
            border_style="cyan",
        )
    )


@app.command()
def version() -> None:
    """Sürümü göster."""
    console.print(f"VulnPilot {__version__}")


@app.command()
def tools() -> None:
    """Kayıtlı araçları ve kullanılabilirliklerini listele."""
    settings = Settings.load()
    orch = Orchestrator(settings)
    table = Table(title="VulnPilot Araçları", show_lines=False)
    table.add_column("Araç", style="cyan")
    table.add_column("Durum")
    table.add_column("Açıklama", style="dim")
    for tool in orch.all_tools():
        ok = tool.is_available()
        status = "[green]✓ hazır[/]" if ok else "[yellow]✗ kurulu değil[/]"
        table.add_row(tool.name, status, tool.description)
    console.print(table)
    console.print(
        "\nAI beyni: "
        + ("[green]açık[/]" if settings.ai_enabled else "[yellow]kapalı (ANTHROPIC_API_KEY yok)[/]")
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Hedef URL veya host (ör. https://ornek.com)"),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Yetki onayını atla (yalnızca izinli hedeflerde!)."
    ),
    output: Path = typer.Option(
        None, "--output", "-o", help="Rapor çıktı klasörü (varsayılan: reports/)."
    ),
    open_report: bool = typer.Option(
        False, "--open", help="Bitince HTML raporu tarayıcıda aç."
    ),
) -> None:
    """Bir hedefi tara ve JSON/Markdown/HTML rapor üret."""
    _banner()
    settings = Settings.load()
    if output:
        settings.output_dir = output

    # --- scope & authorization ---
    try:
        tgt = normalize_target(target)
        tgt = authorize(tgt, assume_yes=yes)
    except ScopeError as exc:
        console.print(f"[red]✗ {exc}[/]")
        raise typer.Exit(code=2) from None

    kind = "lokal/özel" if is_private(tgt.hostname) else "dış hedef"
    console.print(f"\n[bold]Hedef:[/] {tgt.url}  [dim]({kind})[/]")

    brain = Brain(settings)
    orch = Orchestrator(settings, brain)

    avail = [t.name for t in orch.available_tools()]
    console.print(f"[dim]Kullanılabilir araçlar:[/] {', '.join(avail)}")
    console.print(
        "[dim]AI beyni:[/] " + ("[green]açık[/]" if brain.online else "[yellow]kapalı[/]") + "\n"
    )

    def on_event(event: str, detail: str) -> None:
        icons = {
            "plan": "🧠", "plan_done": "📋", "run": "▶",
            "run_done": "✓", "summary": "📝",
        }
        console.print(f"  {icons.get(event, '·')} {detail}")

    with console.status("[cyan]Tarama sürüyor…[/]", spinner="dots"):
        report = orch.scan(tgt, on_event=on_event)

    _print_summary(report)

    stem = f"{tgt.hostname}_{report.finished_at:%Y%m%d-%H%M%S}"
    paths = write_all(report, settings.output_dir, stem)
    console.print("\n[bold green]Raporlar yazıldı:[/]")
    for kind_, path in paths.items():
        console.print(f"  [cyan]{kind_:5}[/] {path}")

    if open_report:
        import webbrowser

        webbrowser.open(paths["html"].resolve().as_uri())


def _print_summary(report: ScanReport) -> None:
    counts = report.severity_counts()
    table = Table(title="\nÖzet", show_header=True)
    for label in counts:
        table.add_column(label, justify="center")
    table.add_row(*[str(counts[label]) for label in counts])
    console.print(table)
    console.print(Panel(report.summary or "Özet yok.", title="Yönetici Özeti", border_style="cyan"))


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]İptal edildi.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()

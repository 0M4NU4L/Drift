"""Drift CLI — Typer-based command interface.

Commands:
    drift analyze <path>   — Parse, build architecture, generate STRIDE threats
    drift baseline <path>  — Create drift.lock snapshot
    drift diff <path>      — Compare against baseline, show threat delta
    drift report <path>    — Generate THREAT_REPORT.md
    drift github <path>    — Generate and post PR comment
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from drift import __version__

app = typer.Typer(
    name="drift",
    help="🔒 Drift — Continuous Architecture Drift Detection & Threat Modeling",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


def _run_analysis(
    target: str,
    no_ai: bool = False,
    output: str = ".",
) -> "AnalysisResult":
    """Core analysis pipeline: parse → build → STRIDE → (AI) → result.

    Shared by analyze, baseline, diff, report, and github commands.
    """
    from drift.parser import parse_directory
    from drift.engine.architecture_builder import build_architecture
    from drift.engine.rule_engine import analyze as stride_analyze
    from drift.engine.drift_engine import compute_delta
    from drift.engine.ai_engine import AIEngine
    from drift.baseline.baseline_manager import load_baseline
    from drift.models import AnalysisResult

    target_path = Path(target).resolve()

    # Step 1: Parse inputs
    console.print("\n[bold cyan]>[/bold cyan] Parsing input files...", highlight=False)
    partial_arch = parse_directory(str(target_path))

    if not partial_arch.components:
        console.print(
            "[yellow]⚠ No infrastructure files found.[/yellow] "
            "Drift looks for: docker-compose*.yml, *.tf, *.yaml (K8s), architecture.json"
        )
        raise typer.Exit(1)

    console.print(
        f"  Found [bold]{len(partial_arch.components)}[/bold] components "
        f"from {len(set(c.source for c in partial_arch.components))} source(s)"
    )

    # Step 2: Build architecture
    console.print("[bold cyan]>[/bold cyan] Building architecture graph...", highlight=False)
    architecture = build_architecture(partial_arch)
    console.print(
        f"  [bold]{len(architecture.components)}[/bold] components, "
        f"[bold]{len(architecture.flows)}[/bold] flows, "
        f"[bold]{len(architecture.boundaries)}[/bold] boundaries, "
        f"[bold]{len(architecture.assets)}[/bold] assets"
    )

    # Step 3: Run STRIDE analysis
    console.print("[bold cyan]>[/bold cyan] Running STRIDE analysis...", highlight=False)
    threats = stride_analyze(architecture)
    console.print(f"  Generated [bold]{len(threats)}[/bold] threats")

    # Step 4: AI augmentation (optional)
    ai_enhanced = False
    if not no_ai:
        console.print("[bold cyan]>[/bold cyan] AI augmentation...", highlight=False)
        ai = AIEngine()
        if ai.is_available:
            threats = ai.enhance_threats(threats, architecture)
            threats = ai.prioritize_threats(threats)
            ai_enhanced = True
            console.print("  [green]OK[/green] Threats enhanced with AI explanations")
        else:
            console.print("  [dim]Skipped (no API key configured)[/dim]")

    # Step 5: Compute delta against baseline
    baseline = load_baseline(str(target_path / ".drift" / "drift.lock"))
    delta = compute_delta(architecture, threats, baseline)

    return AnalysisResult(
        architecture=architecture,
        threats=threats,
        delta=delta,
        ai_enhanced=ai_enhanced,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@app.command()
def analyze(
    target: Annotated[str, typer.Argument(help="Path to analyze (directory with infra files)")] = ".",
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI augmentation")] = False,
    output: Annotated[str, typer.Option("--output", "-o", help="Output directory")] = ".",
):
    """Analyze architecture and generate STRIDE threats."""
    from drift.report.rich_output import display_analysis

    result = _run_analysis(target, no_ai=no_ai, output=output)
    console.print()
    display_analysis(result)


@app.command()
def baseline(
    target: Annotated[str, typer.Argument(help="Path to analyze")] = ".",
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI augmentation")] = False,
):
    """Create a drift.lock baseline snapshot."""
    from drift.baseline.baseline_manager import save_baseline
    from drift.models import Baseline

    result = _run_analysis(target, no_ai=no_ai)

    baseline_data = Baseline(
        architecture=result.architecture,
        threats=result.threats,
    )

    lock_path = str(Path(target).resolve() / ".drift" / "drift.lock")
    saved_path = save_baseline(baseline_data, lock_path)

    console.print(
        f"\n[bold green]OK[/bold green] Baseline saved to [cyan]{saved_path}[/cyan]"
    )
    console.print(
        f"  Components: [bold]{len(result.architecture.components)}[/bold] | "
        f"Threats: [bold]{len(result.threats)}[/bold] | "
        f"Boundaries: [bold]{len(result.architecture.boundaries)}[/bold]"
    )


@app.command()
def diff(
    target: Annotated[str, typer.Argument(help="Path to analyze")] = ".",
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI augmentation")] = False,
):
    """Compare current state against baseline and show threat delta."""
    from drift.report.rich_output import display_delta, display_analysis
    from drift.baseline.baseline_manager import load_baseline

    target_path = Path(target).resolve()
    lock_path = str(target_path / ".drift" / "drift.lock")

    existing_baseline = load_baseline(lock_path)
    if existing_baseline is None:
        console.print(
            "[yellow]⚠ No baseline found.[/yellow] Run [bold]drift baseline .[/bold] first."
        )
        raise typer.Exit(1)

    result = _run_analysis(target, no_ai=no_ai)

    console.print()
    if result.delta and result.delta.has_changes:
        display_delta(result.delta)
    else:
        console.print("[bold green]OK[/bold green] No drift detected. Threat model is stable.\n")


@app.command()
def report(
    target: Annotated[str, typer.Argument(help="Path to analyze")] = ".",
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI augmentation")] = False,
    output: Annotated[str, typer.Option("--output", "-o", help="Output file path")] = "THREAT_REPORT.md",
):
    """Generate a Markdown threat report."""
    from drift.report.markdown_report import generate_report

    result = _run_analysis(target, no_ai=no_ai)
    report_path = generate_report(result, output)

    console.print(
        f"\n[bold green]OK[/bold green] Report saved to [cyan]{report_path}[/cyan]"
    )


@app.command()
def github(
    target: Annotated[str, typer.Argument(help="Path to analyze")] = ".",
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI augmentation")] = False,
):
    """Generate and post a PR comment with threat delta."""
    from drift.github.pr_comment import run_github_mode

    result = _run_analysis(target, no_ai=no_ai)
    run_github_mode(result)


@app.command()
def version():
    """Show Drift version."""
    console.print(f"[bold]Drift[/bold] v{__version__}")


def _version_callback(value: bool):
    if value:
        console.print(f"[bold]Drift[/bold] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", callback=_version_callback, is_eager=True, help="Show version"),
    ] = None,
):
    """🔒 Drift — Keep threat models alive as architectures evolve."""
    pass

"""Rich terminal dashboard for Drift analysis results."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich import box
from rich.text import Text

from drift.models import AnalysisResult, Severity, ThreatDelta, TrustZone

console = Console()

_SEV_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

_SEV_ICONS = {
    Severity.CRITICAL: "[C]",
    Severity.HIGH: "[H]",
    Severity.MEDIUM: "[M]",
    Severity.LOW: "[L]",
}


def display_analysis(result: AnalysisResult) -> None:
    """Display the full analysis dashboard in the terminal."""
    arch = result.architecture
    threats = result.threats
    
    # 1. Header
    header = Panel(
        "[bold white]DRIFT ANALYSIS[/bold white]",
        border_style="cyan",
        box=box.DOUBLE,
        expand=False,
    )
    console.print(header, justify="center")
    console.print()

    # 2. Architecture Summary
    arch_table = Table(box=None, show_header=False)
    arch_table.add_column("Key", style="dim")
    arch_table.add_column("Value", style="bold")
    arch_table.add_row("Components:", str(len(arch.components)))
    arch_table.add_row("Trust Boundaries:", str(len(arch.boundaries)))
    arch_table.add_row("Data Flows:", str(len(arch.flows)))
    arch_table.add_row("Assets Discovered:", str(len(arch.assets)))
    
    arch_panel = Panel(
        arch_table,
        title="[bold]Architecture[/bold]",
        border_style="blue",
        box=box.ROUNDED,
    )

    # 3. Threat Summary
    sev_counts = {s: 0 for s in Severity}
    for t in threats:
        sev_counts[t.severity] += 1
        
    threat_table = Table(box=None, show_header=False)
    for sev in Severity:
        count = sev_counts[sev]
        color = _SEV_COLORS[sev]
        icon = _SEV_ICONS[sev]
        threat_table.add_row(f"{icon} {sev.value.capitalize()}:", f"[{color}]{count}[/{color}]")
        
    threat_panel = Panel(
        threat_table,
        title="[bold]Threat Summary[/bold]",
        border_style="red",
        box=box.ROUNDED,
    )
    
    # Print side-by-side
    console.print(Columns([arch_panel, threat_panel], expand=True))
    console.print()

    # 4. Architecture Tree (Grouped by Zone)
    tree = Tree("[bold]Trust Zones[/bold]")
    zones: dict[TrustZone, list] = {}
    for comp in arch.components:
        zones.setdefault(comp.trust_zone, []).append(comp)
        
    for zone, comps in zones.items():
        zone_node = tree.add(f"[cyan]{zone.value}[/cyan]")
        for comp in comps:
            zone_node.add(f"[green]{comp.name}[/green] [dim]({comp.type.value})[/dim]")
            
    console.print(Panel(tree, title="[bold]Topology[/bold]", border_style="green", box=box.ROUNDED))
    console.print()

    # 5. Delta (if exists)
    if result.delta and result.delta.has_changes:
        display_delta(result.delta)
        console.print()

    # 6. Top Threats Table
    if threats:
        table = Table(
            title="[bold]Identified Threats[/bold]",
            box=box.SIMPLE,
            header_style="bold magenta",
        )
        table.add_column("Severity", justify="left")
        table.add_column("Confidence", justify="right")
        table.add_column("Category", justify="left")
        table.add_column("Title", style="white")
        table.add_column("Boundary", style="dim")
        
        # Sort by severity
        sorted_threats = sorted(
            threats, 
            key=lambda t: list(Severity).index(t.severity)
        )
        
        for t in sorted_threats:
            color = _SEV_COLORS[t.severity]
            icon = _SEV_ICONS[t.severity]
            conf_percent = int(t.confidence * 100)
            conf_color = "green" if conf_percent >= 90 else ("yellow" if conf_percent >= 75 else "red")
            
            table.add_row(
                f"[{color}]{icon} {t.severity.value.upper()}[/{color}]",
                f"[{conf_color}]{conf_percent}%[/{conf_color}]",
                t.stride_category.value,
                t.title,
                t.boundary,
            )
            
        console.print(table)
        
        if result.ai_enhanced:
            console.print("[dim italic]* Threat details enhanced by AI[/dim italic]", justify="right")


def display_delta(delta: ThreatDelta) -> None:
    """Display threat delta panel."""
    delta_text = Text()
    
    if delta.new_threats:
        delta_text.append(f"+ {len(delta.new_threats)} New Threats\n", style="bold red")
    if delta.mitigated_threats:
        delta_text.append(f"- {len(delta.mitigated_threats)} Mitigated Threats\n", style="bold green")
    if delta.new_components:
        delta_text.append(f"+ New components: {', '.join(delta.new_components)}\n", style="cyan")
    if delta.removed_components:
        delta_text.append(f"- Removed components: {', '.join(delta.removed_components)}\n", style="dim")
    if delta.new_boundaries:
        delta_text.append(f"+ {len(delta.new_boundaries)} New boundaries\n", style="yellow")
    if delta.removed_boundaries:
        delta_text.append(f"- {len(delta.removed_boundaries)} Removed boundaries\n", style="dim")
        
    console.print(Panel(
        delta_text,
        title="[bold]Drift Detected[/bold]",
        border_style="yellow",
        box=box.HEAVY,
    ))

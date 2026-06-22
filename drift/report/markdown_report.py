"""Markdown report generator."""

from datetime import datetime, timezone
import logging

from drift import __version__
from drift.models import AnalysisResult, Severity

logger = logging.getLogger(__name__)

_SEV_ICONS = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
}


def generate_report(result: AnalysisResult, output_path: str = "THREAT_REPORT.md") -> str:
    """Generate a markdown threat report and save it to output_path."""
    arch = result.architecture
    threats = result.threats
    delta = result.delta
    
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    lines = [
        "# 🔒 Drift Threat Report",
        f"*Generated on {now}*\n",
    ]
    
    # ---------------------------------------------------------
    # Executive Summary
    # ---------------------------------------------------------
    lines.extend([
        "## Executive Summary\n",
        f"- **Components:** {len(arch.components)}",
        f"- **Trust Boundaries:** {len(arch.boundaries)}",
        f"- **Data Flows:** {len(arch.flows)}",
        f"- **Assets Discovered:** {len(arch.assets)}\n",
    ])
    
    if threats:
        sev_counts = {s: 0 for s in Severity}
        for t in threats:
            sev_counts[t.severity] += 1
            
        lines.append("**Threats by Severity:**")
        for sev in Severity:
            if sev_counts[sev] > 0:
                lines.append(f"- {_SEV_ICONS[sev]}: {sev_counts[sev]}")
        lines.append("")
    else:
        lines.append("**No threats identified.**\n")
        
    # ---------------------------------------------------------
    # Threat Delta
    # ---------------------------------------------------------
    if delta and delta.has_changes:
        lines.extend([
            "## Threat Delta (Changes since baseline)\n"
        ])
        if delta.new_threats:
            lines.append("### ➕ New Threats")
            for t in delta.new_threats:
                lines.append(f"- **{_SEV_ICONS[t.severity]}** | {t.title} ({t.boundary})")
            lines.append("")
            
        if delta.mitigated_threats:
            lines.append("### ➖ Mitigated Threats")
            for t in delta.mitigated_threats:
                lines.append(f"- ~~{t.title}~~")
            lines.append("")
            
        if delta.new_components or delta.removed_components:
            lines.append("### 🏗 Architecture Changes")
            if delta.new_components:
                lines.append(f"- **Added components:** {', '.join(delta.new_components)}")
            if delta.removed_components:
                lines.append(f"- **Removed components:** {', '.join(delta.removed_components)}")
            lines.append("")
            
        if delta.new_boundaries or delta.removed_boundaries:
            lines.append("### 🚧 Boundary Changes")
            if delta.new_boundaries:
                lines.append(f"- **Added boundaries:** {', '.join(delta.new_boundaries)}")
            if delta.removed_boundaries:
                lines.append(f"- **Removed boundaries:** {', '.join(delta.removed_boundaries)}")
            lines.append("")
            
    # ---------------------------------------------------------
    # Threats Detail
    # ---------------------------------------------------------
    if threats:
        lines.extend([
            "## Detailed Threats\n"
        ])
        
        sorted_threats = sorted(threats, key=lambda t: list(Severity).index(t.severity))
        
        for t in sorted_threats:
            conf_percent = int(t.confidence * 100)
            lines.extend([
                f"### {_SEV_ICONS[t.severity]} | {t.title}",
                f"- **STRIDE Category:** {t.stride_category.value}",
                f"- **Boundary Crossed:** {t.boundary}",
                f"- **Affected Components:** {', '.join(t.affected_components)}",
                f"- **Confidence:** {conf_percent}%",
                "- **Evidence:**"
            ])
            for ev in t.evidence:
                lines.append(f"  - `{ev}`")
            
            lines.extend([
                "",
                "**Explanation:**",
                t.explanation,
                "",
                "**Mitigation:**",
                t.mitigation,
                "",
                "---"
            ])
            
    # ---------------------------------------------------------
    # Architecture Overview
    # ---------------------------------------------------------
    lines.extend([
        "## Architecture Overview\n",
        "### Components\n",
        "| Name | Type | Trust Zone | Exposed Ports |",
        "|------|------|------------|---------------|",
    ])
    for c in sorted(arch.components, key=lambda c: c.name):
        ports = ", ".join(str(p) for p in c.exposed_ports) or "-"
        lines.append(f"| {c.name} | {c.type.value} | {c.trust_zone.value} | {ports} |")
    lines.append("")
    
    # ---------------------------------------------------------
    # Trust Boundaries
    # ---------------------------------------------------------
    lines.extend([
        "### Trust Boundaries\n",
        "| Name | Description | Components Involved |",
        "|------|-------------|---------------------|",
    ])
    for b in sorted(arch.boundaries, key=lambda b: b.name):
        comps = ", ".join(b.components) or "-"
        lines.append(f"| {b.name} | {b.description} | {comps} |")
    lines.append("")
    
    # ---------------------------------------------------------
    # Data Flows
    # ---------------------------------------------------------
    lines.extend([
        "### Data Flows\n",
        "| Source | Destination | Protocol | Encrypted | Authenticated |",
        "|--------|-------------|----------|-----------|---------------|",
    ])
    for f in sorted(arch.flows, key=lambda f: f.label):
        enc = "✅" if f.is_encrypted else "❌"
        auth = "✅" if f.is_authenticated else "❌"
        lines.append(f"| {f.source} | {f.destination} | {f.protocol} | {enc} | {auth} |")
    lines.append("")

    # ---------------------------------------------------------
    # Assets
    # ---------------------------------------------------------
    if arch.assets:
        lines.extend([
            "### Sensitive Assets\n",
            "| Name | Type | Location | Description |",
            "|------|------|----------|-------------|",
        ])
        for a in sorted(arch.assets, key=lambda a: a.name):
            lines.append(f"| {a.name} | {a.type.value} | {a.location} | {a.description} |")
        lines.append("")

    lines.append(f"\n---\n*Generated by [Drift](https://github.com/drift-cli) v{__version__}*")
    
    content = "\n".join(lines)
    
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        logger.error(f"Failed to write report to {output_path}: {e}")
        
    return output_path

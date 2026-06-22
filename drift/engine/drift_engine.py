"""Drift Engine — compares current architecture against baseline to produce threat deltas.

This is the core differentiator of Drift. It answers:
"What changed in our threat model since last time?"
"""

from __future__ import annotations

from typing import Optional

from drift.models import (
    Architecture,
    Baseline,
    Threat,
    ThreatDelta,
)


def compute_delta(
    current_architecture: Architecture,
    current_threats: list[Threat],
    baseline: Optional[Baseline],
) -> ThreatDelta:
    """Compare current analysis against a baseline and produce a threat delta.

    If no baseline exists (first run), everything is "new".

    Args:
        current_architecture: The current architecture analysis.
        current_threats: Threats generated from the current architecture.
        baseline: Previously saved baseline (drift.lock), or None.

    Returns:
        ThreatDelta with new/mitigated threats and component/boundary changes.
    """
    if baseline is None:
        # First run — everything is new
        return ThreatDelta(
            new_threats=current_threats,
            mitigated_threats=[],
            new_components=[c.name for c in current_architecture.components],
            removed_components=[],
            new_boundaries=[b.name for b in current_architecture.boundaries],
            removed_boundaries=[],
        )

    # -----------------------------------------------------------------------
    # Compare threats
    # -----------------------------------------------------------------------
    old_threat_ids = {t.id for t in baseline.threats}
    new_threat_ids = {t.id for t in current_threats}

    new_threats = [t for t in current_threats if t.id not in old_threat_ids]
    mitigated_threats = [t for t in baseline.threats if t.id not in new_threat_ids]

    # -----------------------------------------------------------------------
    # Compare components
    # -----------------------------------------------------------------------
    old_component_names = {c.name for c in baseline.architecture.components}
    new_component_names = {c.name for c in current_architecture.components}

    added_components = sorted(new_component_names - old_component_names)
    removed_components = sorted(old_component_names - new_component_names)

    # -----------------------------------------------------------------------
    # Compare boundaries
    # -----------------------------------------------------------------------
    old_boundary_names = {b.name for b in baseline.architecture.boundaries}
    new_boundary_names = {b.name for b in current_architecture.boundaries}

    added_boundaries = sorted(new_boundary_names - old_boundary_names)
    removed_boundaries = sorted(old_boundary_names - new_boundary_names)

    return ThreatDelta(
        new_threats=new_threats,
        mitigated_threats=mitigated_threats,
        new_components=added_components,
        removed_components=removed_components,
        new_boundaries=added_boundaries,
        removed_boundaries=removed_boundaries,
    )


def summarize_delta(delta: ThreatDelta) -> str:
    """Produce a human-readable summary of the threat delta."""
    if not delta.has_changes:
        return "No changes detected. Threat model is stable."

    lines = []

    if delta.new_threats:
        by_severity: dict[str, int] = {}
        for t in delta.new_threats:
            by_severity[t.severity.value] = by_severity.get(t.severity.value, 0) + 1
        severity_parts = [f"{count} {sev}" for sev, count in by_severity.items()]
        lines.append(f"+ {len(delta.new_threats)} new threats ({', '.join(severity_parts)})")

    if delta.mitigated_threats:
        lines.append(f"- {len(delta.mitigated_threats)} mitigated threats")

    if delta.new_components:
        lines.append(f"+ {len(delta.new_components)} new components: {', '.join(delta.new_components)}")

    if delta.removed_components:
        lines.append(f"- {len(delta.removed_components)} removed components: {', '.join(delta.removed_components)}")

    if delta.new_boundaries:
        lines.append(f"+ {len(delta.new_boundaries)} new boundaries")

    if delta.removed_boundaries:
        lines.append(f"- {len(delta.removed_boundaries)} removed boundaries")

    return "\n".join(lines)

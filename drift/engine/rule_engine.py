"""Rule Engine — deterministic STRIDE threat generation and risk scoring.

This engine does NOT use AI. It applies rule-based analysis to generate
STRIDE threats for every data flow that crosses a trust boundary.
Every threat is produced with evidence and boundary context.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from drift.models import (
    Architecture,
    Asset,
    AssetType,
    Component,
    ComponentType,
    DataFlow,
    Severity,
    StrideCategory,
    Threat,
    TrustBoundary,
    TrustZone,
)


# ---------------------------------------------------------------------------
# Risk scoring matrix
# ---------------------------------------------------------------------------

def _risk_score(likelihood: int, impact: int) -> Severity:
    """Calculate severity from likelihood × impact (1-5 each)."""
    score = likelihood * impact
    if score >= 20:
        return Severity.CRITICAL
    if score >= 12:
        return Severity.HIGH
    if score >= 6:
        return Severity.MEDIUM
    return Severity.LOW


def _threat_id(category: StrideCategory, title: str, boundary: str) -> str:
    """Generate a deterministic threat ID."""
    content = f"{category.value}:{title}:{boundary}"
    return hashlib.sha256(content.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Zone risk weights — how risky is traffic crossing between these zones?
# ---------------------------------------------------------------------------

_ZONE_RISK: dict[tuple[TrustZone, TrustZone], int] = {
    # Public Internet crossings are highest risk
    (TrustZone.PUBLIC_INTERNET, TrustZone.INTERNAL_SERVICES): 5,
    (TrustZone.PUBLIC_INTERNET, TrustZone.PCI_ZONE): 5,
    (TrustZone.PUBLIC_INTERNET, TrustZone.DATABASE_TIER): 5,
    (TrustZone.PUBLIC_INTERNET, TrustZone.ADMIN_ZONE): 5,
    (TrustZone.PUBLIC_INTERNET, TrustZone.DMZ): 4,
    # DMZ crossings
    (TrustZone.DMZ, TrustZone.INTERNAL_SERVICES): 3,
    (TrustZone.DMZ, TrustZone.PCI_ZONE): 4,
    (TrustZone.DMZ, TrustZone.DATABASE_TIER): 4,
    (TrustZone.DMZ, TrustZone.ADMIN_ZONE): 4,
    # Internal to sensitive zones
    (TrustZone.INTERNAL_SERVICES, TrustZone.DATABASE_TIER): 2,
    (TrustZone.INTERNAL_SERVICES, TrustZone.PCI_ZONE): 3,
    (TrustZone.INTERNAL_SERVICES, TrustZone.ADMIN_ZONE): 3,
    (TrustZone.INTERNAL_SERVICES, TrustZone.THIRD_PARTY): 3,
    # PCI zone
    (TrustZone.PCI_ZONE, TrustZone.THIRD_PARTY): 4,
    (TrustZone.PCI_ZONE, TrustZone.DATABASE_TIER): 3,
}


def _get_zone_risk(zone_from: TrustZone, zone_to: TrustZone) -> int:
    """Get risk weight for a zone crossing. Higher = more risky."""
    return _ZONE_RISK.get((zone_from, zone_to), _ZONE_RISK.get((zone_to, zone_from), 2))


# ---------------------------------------------------------------------------
# Asset sensitivity weights
# ---------------------------------------------------------------------------

_ASSET_SENSITIVITY: dict[AssetType, int] = {
    AssetType.CARD_DATA: 5,
    AssetType.CREDENTIALS: 5,
    AssetType.ENCRYPTION_KEYS: 5,
    AssetType.API_KEYS: 4,
    AssetType.TOKENS: 4,
    AssetType.PII: 4,
    AssetType.SESSION_DATA: 3,
    AssetType.UNKNOWN: 2,
}


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def analyze(architecture: Architecture) -> list[Threat]:
    """Run deterministic STRIDE analysis on the architecture.

    For every data flow that crosses a trust boundary, generates
    applicable STRIDE threats with evidence and risk scores.
    Also checks for architectural anti-patterns.
    """
    threats: list[Threat] = []
    comp_map = {c.name: c for c in architecture.components}

    # 1. Analyze boundary-crossing flows
    for flow in architecture.flows:
        src = comp_map.get(flow.source)
        dst = comp_map.get(flow.destination)

        if not src or not dst:
            continue

        # Only generate threats for cross-boundary flows
        if src.trust_zone == dst.trust_zone:
            continue

        flow_threats = _analyze_flow(flow, src, dst, architecture)
        threats.extend(flow_threats)

    # 2. Analyze component-level issues
    for comp in architecture.components:
        comp_threats = _analyze_component(comp, architecture)
        threats.extend(comp_threats)

    # 3. Analyze asset exposure
    for asset in architecture.assets:
        asset_threats = _analyze_asset(asset, comp_map, architecture)
        threats.extend(asset_threats)

    # Deduplicate by ID
    seen_ids: set[str] = set()
    unique_threats: list[Threat] = []
    for threat in threats:
        if threat.id not in seen_ids:
            seen_ids.add(threat.id)
            unique_threats.append(threat)

    return unique_threats


def _analyze_flow(
    flow: DataFlow,
    src: Component,
    dst: Component,
    arch: Architecture,
) -> list[Threat]:
    """Generate STRIDE threats for a single cross-boundary data flow."""
    threats: list[Threat] = []
    boundary = f"{src.trust_zone.value} -> {dst.trust_zone.value}"
    zone_risk = _get_zone_risk(src.trust_zone, dst.trust_zone)
    affected = [src.name, dst.name]

    # -----------------------------------------------------------------------
    # SPOOFING — Can someone impersonate the source?
    # -----------------------------------------------------------------------
    if not flow.is_authenticated:
        likelihood = min(zone_risk, 5)
        impact = 4 if dst.type in (ComponentType.DATABASE, ComponentType.SERVERLESS) else 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.SPOOFING, f"Unauthenticated flow: {flow.label}", boundary),
            stride_category=StrideCategory.SPOOFING,
            title=f"Unauthenticated flow: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=f"{flow.label} has no authentication mechanism",
            boundary=boundary,
            explanation=(
                f"Traffic from {src.name} ({src.trust_zone.value}) to {dst.name} "
                f"({dst.trust_zone.value}) lacks authentication. An attacker could "
                f"impersonate {src.name} to access {dst.name}."
            ),
            mitigation="Implement mutual TLS (mTLS) or service-to-service authentication tokens",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # TAMPERING — Can someone modify data in transit?
    # -----------------------------------------------------------------------
    if not flow.is_encrypted:
        likelihood = min(zone_risk, 5)
        impact = 4
        protocol_info = f" over {flow.protocol.upper()}" if flow.protocol != "unknown" else ""
        threats.append(Threat(
            id=_threat_id(StrideCategory.TAMPERING, f"Unencrypted flow: {flow.label}", boundary),
            stride_category=StrideCategory.TAMPERING,
            title=f"Unencrypted traffic: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=f"{flow.label}{protocol_info} is not encrypted",
            boundary=boundary,
            explanation=(
                f"Data flowing from {src.name} to {dst.name} crosses from "
                f"{src.trust_zone.value} to {dst.trust_zone.value} without encryption. "
                f"An attacker on the network path could modify data in transit."
            ),
            mitigation="Enforce TLS 1.3 for all cross-boundary communications",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # INFORMATION DISCLOSURE — Can someone read data in transit?
    # -----------------------------------------------------------------------
    if not flow.is_encrypted:
        likelihood = min(zone_risk + 1, 5)
        # Higher impact if sensitive data classification
        impact = 5 if flow.data_classification in (
            "authentication_data", "payment_data", "pii", "persistent_data"
        ) else 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Plaintext data: {flow.label}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Plaintext data exposure: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=f"{flow.label} transmits data without encryption",
            boundary=boundary,
            explanation=(
                f"Data from {src.name} to {dst.name} traverses "
                f"{src.trust_zone.value} to {dst.trust_zone.value} in plaintext. "
                f"Sensitive information could be intercepted by network observers."
            ),
            mitigation="Enable TLS 1.3 and enforce HTTPS-only communication",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # REPUDIATION — Is there audit logging?
    # -----------------------------------------------------------------------
    # We can't directly observe logging, but cross-boundary flows should be logged
    if zone_risk >= 3:
        threats.append(Threat(
            id=_threat_id(StrideCategory.REPUDIATION, f"Cross-boundary audit: {flow.label}", boundary),
            stride_category=StrideCategory.REPUDIATION,
            title=f"Missing audit trail: {src.name} -> {dst.name}",
            severity=_risk_score(2, 3),
            evidence=f"Cross-boundary flow {flow.label} crosses a high-risk boundary",
            boundary=boundary,
            explanation=(
                f"Traffic crossing from {src.trust_zone.value} to {dst.trust_zone.value} "
                f"should be logged for audit and forensics. Without logging, malicious "
                f"actions cannot be traced back to their source."
            ),
            mitigation="Implement centralized logging with correlation IDs for all cross-boundary traffic",
            affected_components=affected,
            likelihood=2,
            impact=3,
        ))

    # -----------------------------------------------------------------------
    # DENIAL OF SERVICE — Can the destination be overwhelmed?
    # -----------------------------------------------------------------------
    if src.trust_zone in (TrustZone.PUBLIC_INTERNET, TrustZone.DMZ):
        likelihood = 4 if src.trust_zone == TrustZone.PUBLIC_INTERNET else 3
        impact = 4 if dst.type in (ComponentType.DATABASE, ComponentType.SERVICE) else 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.DENIAL_OF_SERVICE, f"Public exposure: {dst.name}", boundary),
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            title=f"Denial of service risk: {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=f"{dst.name} receives traffic from {src.trust_zone.value}",
            boundary=boundary,
            explanation=(
                f"{dst.name} in {dst.trust_zone.value} is reachable from "
                f"{src.trust_zone.value}. Without rate limiting and circuit breakers, "
                f"it could be overwhelmed by excessive requests."
            ),
            mitigation="Implement rate limiting, circuit breakers, and auto-scaling",
            affected_components=[dst.name],
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # ELEVATION OF PRIVILEGE — Can access be escalated?
    # -----------------------------------------------------------------------
    if dst.trust_zone in (TrustZone.ADMIN_ZONE, TrustZone.PCI_ZONE, TrustZone.DATABASE_TIER):
        if src.trust_zone in (TrustZone.PUBLIC_INTERNET, TrustZone.DMZ, TrustZone.INTERNAL_SERVICES):
            likelihood = zone_risk
            impact = 5
            threats.append(Threat(
                id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Zone escalation: {flow.label}", boundary),
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                title=f"Privilege escalation path: {src.name} -> {dst.name}",
                severity=_risk_score(likelihood, impact),
                evidence=(
                    f"{src.name} ({src.trust_zone.value}) can reach "
                    f"{dst.name} ({dst.trust_zone.value})"
                ),
                boundary=boundary,
                explanation=(
                    f"A path exists from {src.trust_zone.value} to the sensitive "
                    f"{dst.trust_zone.value} zone. If {src.name} is compromised, "
                    f"an attacker could escalate access to {dst.name}."
                ),
                mitigation="Enforce strict RBAC, network segmentation, and least-privilege access",
                affected_components=affected,
                likelihood=likelihood,
                impact=impact,
            ))

    return threats


def _analyze_component(comp: Component, arch: Architecture) -> list[Threat]:
    """Generate threats from component-level issues."""
    threats: list[Threat] = []
    boundary = f"{comp.trust_zone.value}"

    # Privileged container
    if comp.properties.get("privileged"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Privileged: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Privileged container: {comp.name}",
            severity=Severity.CRITICAL,
            evidence=f"{comp.name} runs in privileged mode",
            boundary=boundary,
            explanation=(
                f"{comp.name} is configured to run with elevated privileges. "
                f"A container escape could give an attacker full host access."
            ),
            mitigation="Remove privileged mode; use specific Linux capabilities instead",
            affected_components=[comp.name],
            likelihood=4,
            impact=5,
        ))

    # Host networking
    if comp.properties.get("host_network"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Host network: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Host network access: {comp.name}",
            severity=Severity.HIGH,
            evidence=f"{comp.name} uses host networking",
            boundary=boundary,
            explanation=(
                f"{comp.name} shares the host's network namespace, bypassing "
                f"container network isolation. It can access all host network traffic."
            ),
            mitigation="Use container networking with explicit port mappings",
            affected_components=[comp.name],
            likelihood=3,
            impact=4,
        ))

    # HTTP allowed explicitly
    env_lower = {k.lower(): v for k, v in comp.environment.items()}
    if env_lower.get("allow_http", "").lower() in ("true", "1", "yes"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"HTTP allowed: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"HTTP explicitly allowed: {comp.name}",
            severity=Severity.HIGH,
            evidence=f"{comp.name} has ALLOW_HTTP=true in environment",
            boundary=boundary,
            explanation=(
                f"{comp.name} explicitly allows unencrypted HTTP traffic. "
                f"Any data sent to or from this service could be intercepted."
            ),
            mitigation="Remove ALLOW_HTTP and enforce HTTPS-only communication",
            affected_components=[comp.name],
            likelihood=4,
            impact=4,
        ))

    # Database exposed to public
    if comp.type == ComponentType.DATABASE:
        if comp.trust_zone in (TrustZone.PUBLIC_INTERNET, TrustZone.DMZ):
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public DB: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Publicly accessible database: {comp.name}",
                severity=Severity.CRITICAL,
                evidence=f"{comp.name} (database) is in {comp.trust_zone.value}",
                boundary=boundary,
                explanation=(
                    f"Database {comp.name} is accessible from {comp.trust_zone.value}. "
                    f"Databases should never be directly reachable from untrusted zones."
                ),
                mitigation="Move database to private subnet; access only through application tier",
                affected_components=[comp.name],
                likelihood=5,
                impact=5,
            ))

    # Overly permissive IAM
    if comp.properties.get("overly_permissive_iam"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Permissive IAM: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Overly permissive IAM policy: {comp.name}",
            severity=Severity.CRITICAL,
            evidence=f"{comp.name} has wildcard (*) IAM permissions",
            boundary=boundary,
            explanation=(
                f"{comp.name} has been granted wildcard permissions (Action: *, Resource: *). "
                f"If this component is compromised, the attacker gains full access to all AWS resources."
            ),
            mitigation="Apply least-privilege IAM policies; scope permissions to specific resources and actions",
            affected_components=[comp.name],
            likelihood=4,
            impact=5,
        ))

    # Public storage
    if comp.properties.get("public_access"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public storage: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Publicly accessible storage: {comp.name}",
            severity=Severity.HIGH,
            evidence=f"{comp.name} has public access enabled",
            boundary=boundary,
            explanation=(
                f"Storage resource {comp.name} allows public access. "
                f"Any data stored here could be accessed by anyone on the internet."
            ),
            mitigation="Enable block public access settings; use IAM policies for access control",
            affected_components=[comp.name],
            likelihood=4,
            impact=4,
        ))

    # Missing encryption at rest for databases
    if comp.type == ComponentType.DATABASE and not comp.properties.get("encrypted"):
        if comp.properties.get("has_encryption_config") is False:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"No encryption: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Missing encryption at rest: {comp.name}",
                severity=Severity.HIGH,
                evidence=f"{comp.name} does not have encryption at rest configured",
                boundary=boundary,
                explanation=(
                    f"Database {comp.name} stores data without encryption at rest. "
                    f"Physical access to storage media could expose all stored data."
                ),
                mitigation="Enable storage encryption with managed keys (KMS/AES-256)",
                affected_components=[comp.name],
                likelihood=2,
                impact=5,
            ))

    return threats


def _analyze_asset(
    asset: Asset,
    comp_map: dict[str, Component],
    arch: Architecture,
) -> list[Threat]:
    """Generate threats for sensitive assets."""
    threats: list[Threat] = []
    comp = comp_map.get(asset.location)
    if not comp:
        return threats

    sensitivity = _ASSET_SENSITIVITY.get(asset.type, 2)
    boundary = f"{comp.trust_zone.value}"

    # Credentials or secrets in environment variables
    if asset.type in (AssetType.CREDENTIALS, AssetType.API_KEYS, AssetType.ENCRYPTION_KEYS):
        threats.append(Threat(
            id=_threat_id(
                StrideCategory.INFORMATION_DISCLOSURE,
                f"Secret in env: {asset.name}@{comp.name}",
                boundary,
            ),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Secret in environment: {asset.name}",
            severity=_risk_score(3, sensitivity),
            evidence=f"{asset.name} found in {comp.name} environment variables",
            boundary=boundary,
            explanation=(
                f"Sensitive credential '{asset.name}' is stored as an environment variable "
                f"in {comp.name}. Environment variables can leak through logs, crash dumps, "
                f"and child processes."
            ),
            mitigation="Use a secrets manager (Vault, AWS Secrets Manager) instead of environment variables",
            affected_components=[comp.name],
            likelihood=3,
            impact=sensitivity,
        ))

    # PII in third-party zone
    if asset.type == AssetType.PII and comp.trust_zone == TrustZone.THIRD_PARTY:
        threats.append(Threat(
            id=_threat_id(
                StrideCategory.INFORMATION_DISCLOSURE,
                f"PII at third party: {asset.name}",
                boundary,
            ),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"PII shared with third party: {asset.name}",
            severity=Severity.HIGH,
            evidence=f"PII asset '{asset.name}' located at third-party component {comp.name}",
            boundary=boundary,
            explanation=(
                f"Personally identifiable information ({asset.name}) is stored at or "
                f"shared with third-party service {comp.name}. This creates regulatory "
                f"and privacy risks (GDPR, CCPA)."
            ),
            mitigation="Minimize PII sharing; implement data processing agreements; anonymize where possible",
            affected_components=[comp.name],
            likelihood=3,
            impact=4,
        ))

    # Card data anywhere that isn't PCI zone
    if asset.type == AssetType.CARD_DATA and comp.trust_zone != TrustZone.PCI_ZONE:
        threats.append(Threat(
            id=_threat_id(
                StrideCategory.INFORMATION_DISCLOSURE,
                f"Card data outside PCI: {asset.name}",
                boundary,
            ),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Card data outside PCI zone: {asset.name}",
            severity=Severity.CRITICAL,
            evidence=f"Card data '{asset.name}' in {comp.name} ({comp.trust_zone.value}), not PCI zone",
            boundary=boundary,
            explanation=(
                f"Payment card data ({asset.name}) is handled by {comp.name} which "
                f"is not in the PCI zone. This violates PCI-DSS requirements."
            ),
            mitigation="Move card data handling to PCI-compliant zone; use tokenization",
            affected_components=[comp.name],
            likelihood=3,
            impact=5,
        ))

    return threats

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
    
    is_public_exposure = src.trust_zone == TrustZone.PUBLIC_INTERNET

    # -----------------------------------------------------------------------
    # SPOOFING
    # -----------------------------------------------------------------------
    env_lower = {k.lower(): str(v).lower() for k, v in dst.environment.items()}
    has_no_auth = env_lower.get("no_auth") in ("true", "1", "yes")
    has_anonymous = env_lower.get("anonymous_access") in ("true", "1", "yes")
    
    if has_no_auth or has_anonymous:
        evidence = []
        if has_no_auth: evidence.append("NO_AUTH is enabled")
        if has_anonymous: evidence.append("Anonymous access is enabled")
        
        likelihood = zone_risk
        impact = 4 if dst.type in (ComponentType.DATABASE, ComponentType.SERVERLESS) else 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.SPOOFING, f"Unauthenticated access: {flow.label}", boundary),
            stride_category=StrideCategory.SPOOFING,
            title=f"Unauthenticated access: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=evidence,
            boundary=boundary,
            explanation=f"Traffic from {src.name} to {dst.name} has explicit properties allowing unauthenticated or anonymous access.",
            mitigation="Remove NO_AUTH or anonymous access overrides in production.",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # TAMPERING
    # -----------------------------------------------------------------------
    if not flow.is_encrypted and (is_public_exposure or flow.protocol == "http"):
        likelihood = 4 if is_public_exposure else min(zone_risk, 4)
        impact = 4
        threats.append(Threat(
            id=_threat_id(StrideCategory.TAMPERING, f"Unencrypted flow: {flow.label}", boundary),
            stride_category=StrideCategory.TAMPERING,
            title=f"Unencrypted traffic: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=[f"{flow.label} uses plaintext {flow.protocol.upper()}"],
            boundary=boundary,
            explanation=f"Data between {src.name} and {dst.name} is not encrypted, allowing tampering.",
            mitigation="Enforce TLS 1.3.",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # INFORMATION DISCLOSURE
    # -----------------------------------------------------------------------
    if not flow.is_encrypted:
        likelihood = 5 if is_public_exposure else min(zone_risk + 1, 4)
        impact = 5 if flow.data_classification in ("authentication_data", "payment_data", "pii", "persistent_data") else 3
        
        # Downgrade if it's just public traffic to an API Gateway/LoadBalancer
        if is_public_exposure and dst.type in (ComponentType.API_GATEWAY, ComponentType.LOAD_BALANCER) and impact < 5:
            likelihood = 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Plaintext data: {flow.label}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Plaintext data exposure: {src.name} -> {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=[f"{flow.label} transmits data without encryption"],
            boundary=boundary,
            explanation=f"Sensitive information could be intercepted by network observers.",
            mitigation="Enable TLS 1.3.",
            affected_components=affected,
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # REPUDIATION
    # -----------------------------------------------------------------------
    has_logging_disabled = env_lower.get("logging_disabled") in ("true", "1", "yes")
    if has_logging_disabled:
        threats.append(Threat(
            id=_threat_id(StrideCategory.REPUDIATION, f"Logging disabled: {dst.name}", boundary),
            stride_category=StrideCategory.REPUDIATION,
            title=f"Audit logging disabled: {dst.name}",
            severity=_risk_score(3, 3),
            evidence=["LOGGING_DISABLED=true found in environment"],
            boundary=boundary,
            explanation=f"Audit logging is explicitly disabled for {dst.name}.",
            mitigation="Enable centralized structured logging.",
            affected_components=[dst.name],
            likelihood=3,
            impact=3,
        ))

    # -----------------------------------------------------------------------
    # DENIAL OF SERVICE
    # -----------------------------------------------------------------------
    replicas = dst.properties.get("replicas", 1)
    if is_public_exposure and replicas == 1:
        likelihood = 3
        impact = 3
        threats.append(Threat(
            id=_threat_id(StrideCategory.DENIAL_OF_SERVICE, f"Single replica: {dst.name}", boundary),
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            title=f"Availability concern: {dst.name}",
            severity=_risk_score(likelihood, impact),
            evidence=[f"{dst.name} is exposed publicly with only 1 replica"],
            boundary=boundary,
            explanation=f"{dst.name} has no high availability and is exposed to the public.",
            mitigation="Increase replicas and configure horizontal autoscaling.",
            affected_components=[dst.name],
            likelihood=likelihood,
            impact=impact,
        ))

    # -----------------------------------------------------------------------
    # EXTERNAL EXPOSURE OF SENSITIVE ZONE
    # -----------------------------------------------------------------------
    if dst.trust_zone in (TrustZone.ADMIN_ZONE, TrustZone.PCI_ZONE, TrustZone.DATABASE_TIER):
        if is_public_exposure and not flow.is_authenticated:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"External exposure: {dst.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"External exposure of sensitive zone: {dst.name}",
                severity=Severity.CRITICAL,
                evidence=[f"Unauthenticated public path to {dst.trust_zone.value}"],
                boundary=boundary,
                explanation=f"A direct unauthenticated path exists to a highly sensitive zone.",
                mitigation="Segment the network and enforce strict authentication.",
                affected_components=affected,
                likelihood=5,
                impact=5,
            ))
            threats.append(Threat(
                id=_threat_id(StrideCategory.TAMPERING, f"External exposure: {dst.name}", boundary),
                stride_category=StrideCategory.TAMPERING,
                title=f"External exposure of sensitive zone: {dst.name}",
                severity=Severity.CRITICAL,
                evidence=[f"Unauthenticated public path to {dst.trust_zone.value}"],
                boundary=boundary,
                explanation=f"A direct unauthenticated path exists to a highly sensitive zone.",
                mitigation="Segment the network and enforce strict authentication.",
                affected_components=affected,
                likelihood=5,
                impact=5,
            ))

    return threats


def _analyze_component(comp: Component, arch: Architecture) -> list[Threat]:
    """Generate threats from component-level issues."""
    threats: list[Threat] = []
    boundary = f"{comp.trust_zone.value}"
    
    is_public = comp.trust_zone in (TrustZone.PUBLIC_INTERNET, TrustZone.DMZ)
    properties_str = str(comp.properties).lower()

    # Privileged container
    if comp.properties.get("privileged"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Privileged: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Privileged container: {comp.name}",
            severity=Severity.CRITICAL,
            evidence=[f"{comp.name} runs in privileged mode"],
            boundary=boundary,
            explanation=(
                f"{comp.name} is configured to run with elevated privileges. "
                f"A container escape could give an attacker full host access."
            ),
            mitigation="Remove privileged mode; use specific Linux capabilities instead",
            affected_components=[comp.name],
            likelihood=4,
            impact=5,
            confidence=0.98,
        ))

    # Host networking
    if comp.properties.get("host_network"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Host network: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Host network access: {comp.name}",
            severity=Severity.HIGH,
            evidence=[f"{comp.name} uses host networking"],
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
            evidence=[f"{comp.name} has ALLOW_HTTP=true in environment"],
            boundary=boundary,
            explanation=(
                f"{comp.name} explicitly allows unencrypted HTTP traffic. "
                f"Any data sent to or from this service could be intercepted."
            ),
            mitigation="Remove ALLOW_HTTP and enforce HTTPS-only communication",
            affected_components=[comp.name],
            likelihood=4,
            impact=4,
            confidence=0.90,
        ))

    # POSTGRES DETECTION
    if comp.type == ComponentType.DATABASE or "postgres" in comp.name.lower():
        if 5432 in comp.exposed_ports or "5432" in properties_str or "0.0.0.0/0" in properties_str or is_public:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public DB: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Publicly accessible database: {comp.name}",
                severity=Severity.CRITICAL,
                evidence=[f"5432 exposed or binds to 0.0.0.0/0"],
                boundary=boundary,
                explanation="Databases should never be directly reachable from untrusted zones.",
                mitigation="Move database to private subnet.",
                affected_components=[comp.name],
                likelihood=5,
                impact=5,
            ))

    # REDIS DETECTION
    if comp.type == ComponentType.CACHE or "redis" in comp.name.lower():
        if 6379 in comp.exposed_ports or "6379" in properties_str or "0.0.0.0/0" in properties_str or is_public:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public Cache: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Publicly accessible cache: {comp.name}",
                severity=Severity.CRITICAL,
                evidence=[f"6379 exposed or binds to 0.0.0.0/0"],
                boundary=boundary,
                explanation="Cache stores session or temporary data and should not be public.",
                mitigation="Ensure Redis is only bound to localhost or internal network.",
                affected_components=[comp.name],
                likelihood=5,
                impact=5,
            ))

    # LOADBALANCER DETECTION
    if "loadbalancer" in properties_str or comp.type == ComponentType.LOAD_BALANCER:
        if comp.type not in (ComponentType.DATABASE, ComponentType.CACHE):
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"LB Exposure: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"External service exposure",
                severity=Severity.HIGH,
                evidence=[f"Service type = LoadBalancer"],
                boundary=boundary,
                explanation=f"{comp.name} is exposed to the internet via a LoadBalancer.",
                mitigation="Ensure exposure is intended and restrict CIDR blocks if possible.",
                affected_components=[comp.name],
                likelihood=4,
                impact=3,
            ))

    # NETWORK SEGMENTATION
    if comp.trust_zone == TrustZone.DMZ and comp.type in (ComponentType.DATABASE, ComponentType.CACHE):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Flat Network: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Missing network segmentation: {comp.name}",
            severity=Severity.MEDIUM,
            evidence=[f"{comp.name} ({comp.type.value}) is in the DMZ with public services"],
            boundary=boundary,
            explanation="Sensitive assets share trust zones with externally facing services.",
            mitigation="Implement proper network tiers.",
            affected_components=[comp.name],
            likelihood=3,
            impact=4,
        ))

    # Overly permissive IAM
    if comp.properties.get("overly_permissive_iam"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Permissive IAM: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Overly permissive IAM policy: {comp.name}",
            severity=Severity.CRITICAL,
            evidence=[f"{comp.name} has wildcard (*) IAM permissions"],
            boundary=boundary,
            explanation=(
                f"{comp.name} has been granted wildcard permissions (Action: *, Resource: *). "
                f"If this component is compromised, the attacker gains full access to all AWS resources."
            ),
            mitigation="Apply least-privilege IAM policies; scope permissions to specific resources and actions",
            affected_components=[comp.name],
            likelihood=4,
            impact=5,
            confidence=0.98,
        ))

    # OBSERVABILITY (Elasticsearch) DETECTION
    if comp.type == ComponentType.OBSERVABILITY or "elastic" in comp.name.lower():
        if 9200 in comp.exposed_ports or "9200" in properties_str or "0.0.0.0/0" in properties_str or is_public:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public Search: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Public search cluster",
                severity=Severity.HIGH,
                evidence=[f"9200 exposed or binds to 0.0.0.0/0"],
                boundary=boundary,
                explanation="Search clusters contain sensitive telemetry and should not be public.",
                mitigation="Ensure cluster is only bound to internal network.",
                affected_components=[comp.name],
                likelihood=4,
                impact=5,
            ))

    # QUEUE (RabbitMQ) DETECTION
    if comp.type == ComponentType.QUEUE or "rabbit" in comp.name.lower():
        if 5672 in comp.exposed_ports or "5672" in properties_str or "0.0.0.0/0" in properties_str or is_public:
            threats.append(Threat(
                id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public Queue: {comp.name}", boundary),
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                title=f"Public message broker",
                severity=Severity.MEDIUM,
                evidence=[f"5672 exposed or binds to 0.0.0.0/0"],
                boundary=boundary,
                explanation="Message brokers should not be public.",
                mitigation="Ensure broker is only bound to internal network.",
                affected_components=[comp.name],
                likelihood=3,
                impact=4,
            ))

    # Kubernetes: Run as Root
    if comp.properties.get("run_as_root"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Root User: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Container running as root",
            severity=Severity.CRITICAL,
            evidence=[f"{comp.name} has runAsUser=0"],
            boundary=boundary,
            explanation=f"Running as root gives the container full permissions on the host if it escapes.",
            mitigation="Configure runAsNonRoot: true.",
            affected_components=[comp.name],
            likelihood=5,
            impact=5,
        ))

    # Kubernetes: Host Path
    if comp.properties.get("host_path_root"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.ELEVATION_OF_PRIVILEGE, f"Host Path: {comp.name}", boundary),
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            title=f"Host filesystem mounted",
            severity=Severity.CRITICAL,
            evidence=[f"{comp.name} mounts hostPath /"],
            boundary=boundary,
            explanation=f"Mounting the root host filesystem allows the container to overwrite host files.",
            mitigation="Remove hostPath volumes.",
            affected_components=[comp.name],
            likelihood=5,
            impact=5,
            confidence=0.98,
        ))

    # Kubernetes: NodePort
    if comp.properties.get("nodeport"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"NodePort: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"External service exposure",
            severity=Severity.HIGH,
            evidence=[f"{comp.name} is exposed via NodePort"],
            boundary=boundary,
            explanation=f"NodePort exposes the service on every node's IP.",
            mitigation="Use ClusterIP and expose via an Ingress.",
            affected_components=[comp.name],
            likelihood=4,
            impact=4,
            confidence=0.95,
        ))

    # Kubernetes: No Resource Limits
    if comp.properties.get("no_resource_limits"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.DENIAL_OF_SERVICE, f"No Limits: {comp.name}", boundary),
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            title=f"No resource limits defined",
            severity=Severity.MEDIUM,
            evidence=[f"{comp.name} lacks CPU/Memory limits"],
            boundary=boundary,
            explanation=f"A compromised or buggy container could consume all host resources.",
            mitigation="Define resource limits and requests.",
            affected_components=[comp.name],
            likelihood=3,
            impact=3,
        ))

    # Public storage
    if comp.properties.get("public_access"):
        threats.append(Threat(
            id=_threat_id(StrideCategory.INFORMATION_DISCLOSURE, f"Public storage: {comp.name}", boundary),
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            title=f"Public object storage",
            severity=Severity.HIGH,
            evidence=[f"{comp.name} has public access enabled"],
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
            evidence=[f"{asset.name} found in {comp.name} environment variables"],
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
            confidence=0.85,
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
            evidence=[f"PII asset '{asset.name}' located at third-party component {comp.name}"],
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
            evidence=[f"Card data '{asset.name}' in {comp.name} ({comp.trust_zone.value}), not PCI zone"],
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

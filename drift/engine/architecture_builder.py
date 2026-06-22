"""Architecture Builder — constructs a unified architecture graph from parsed inputs.

Uses NetworkX DiGraph to model component relationships, infers trust boundaries,
classifies components, maps data flows, and discovers sensitive assets.
"""

from __future__ import annotations

import re
from typing import Optional

import networkx as nx

from drift.models import (
    Architecture,
    Asset,
    AssetType,
    Component,
    ComponentType,
    DataFlow,
    TrustBoundary,
    TrustZone,
)


# ---------------------------------------------------------------------------
# Component type inference patterns
# ---------------------------------------------------------------------------

_TYPE_PATTERNS: list[tuple[re.Pattern, ComponentType]] = [
    (re.compile(r"(gateway|nginx|traefik|kong|envoy|haproxy|ingress)", re.I), ComponentType.API_GATEWAY),
    (re.compile(r"(postgres|mysql|mariadb|mongo|cockroach|rds|dynamo|database|db)", re.I), ComponentType.DATABASE),
    (re.compile(r"(redis|memcache|elasticache|cache)", re.I), ComponentType.CACHE),
    (re.compile(r"(rabbit|kafka|sqs|sns|nats|queue|broker|mq)", re.I), ComponentType.QUEUE),
    (re.compile(r"(lambda|function|serverless|cloud.?function)", re.I), ComponentType.SERVERLESS),
    (re.compile(r"(s3|bucket|storage|blob|minio)", re.I), ComponentType.STORAGE),
    (re.compile(r"(lb|load.?balancer|alb|elb|nlb)", re.I), ComponentType.LOAD_BALANCER),
    (re.compile(r"(cloudfront|cdn|akamai|fastly)", re.I), ComponentType.CDN),
    (re.compile(r"(proxy|sidecar)", re.I), ComponentType.PROXY),
    (re.compile(r"(elasticsearch|kibana|grafana|prometheus|datadog|splunk|observability|logstash)", re.I), ComponentType.OBSERVABILITY),
]

# Patterns indicating sensitive environment variables
_SENSITIVE_ENV_PATTERNS: list[tuple[re.Pattern, AssetType, str]] = [
    (re.compile(r"(password|passwd|pwd)", re.I), AssetType.CREDENTIALS, "password"),
    (re.compile(r"(secret|private.?key)", re.I), AssetType.CREDENTIALS, "secret"),
    (re.compile(r"(api.?key|access.?key)", re.I), AssetType.API_KEYS, "api_key"),
    (re.compile(r"(token|jwt|bearer|oauth)", re.I), AssetType.TOKENS, "token"),
    (re.compile(r"(stripe|payment|card|cvv|pan)", re.I), AssetType.CARD_DATA, "payment_data"),
    (re.compile(r"(database.?url|db.?host|db.?pass|connection.?string)", re.I), AssetType.CREDENTIALS, "database_credential"),
    (re.compile(r"(email|phone|ssn|address|dob|birth)", re.I), AssetType.PII, "pii"),
    (re.compile(r"(encrypt|cert|tls|ssl)", re.I), AssetType.ENCRYPTION_KEYS, "encryption_key"),
]

# Trust zone assignment rules based on component properties
_PUBLIC_PORTS = {80, 443, 8080, 8443, 3000, 5000}


def build_architecture(partial: Architecture) -> Architecture:
    """Build a complete architecture from parsed partial data.

    Performs:
    1. Component type classification
    2. Trust zone assignment
    3. Data flow enrichment
    4. Trust boundary inference
    5. Asset discovery from environment variables
    """
    # Build the graph
    graph = nx.DiGraph()

    # Step 1: Classify and enrich components
    components = _classify_components(partial.components)

    # Step 2: Assign trust zones
    components = _assign_trust_zones(components, partial.flows)

    # Step 3: Add nodes and edges to graph
    for comp in components:
        graph.add_node(comp.name, component=comp)

    for flow in partial.flows:
        graph.add_edge(
            flow.source,
            flow.destination,
            flow=flow,
        )

    # Step 4: Enrich data flows
    flows = _enrich_flows(partial.flows, {c.name: c for c in components})

    # Step 5: Infer trust boundaries
    boundaries = _infer_boundaries(components, flows, partial.boundaries)

    # Step 6: Discover assets from environment variables
    assets = _discover_assets(components, partial.assets)

    # Step 7: Build metadata
    metadata = {
        **partial.metadata,
        "total_components": len(components),
        "total_flows": len(flows),
        "total_boundaries": len(boundaries),
        "total_assets": len(assets),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
    }

    return Architecture(
        components=components,
        flows=flows,
        boundaries=boundaries,
        assets=assets,
        metadata=metadata,
    )


def _classify_components(components: list[Component]) -> list[Component]:
    """Infer component types from names and images."""
    result = []
    for comp in components:
        if comp.type != ComponentType.UNKNOWN:
            result.append(comp)
            continue

        # Try to match against known patterns
        search_text = f"{comp.name} {comp.image}"
        inferred_type = ComponentType.SERVICE  # default

        for pattern, comp_type in _TYPE_PATTERNS:
            if pattern.search(search_text):
                inferred_type = comp_type
                break
                
        # Port-based fallback
        if inferred_type == ComponentType.SERVICE:
            if 9200 in comp.exposed_ports:
                inferred_type = ComponentType.OBSERVABILITY
            elif 5672 in comp.exposed_ports:
                inferred_type = ComponentType.QUEUE
            elif 6379 in comp.exposed_ports:
                inferred_type = ComponentType.CACHE
            elif 5432 in comp.exposed_ports:
                inferred_type = ComponentType.DATABASE

        result.append(comp.model_copy(update={"type": inferred_type}))
    return result


def _assign_trust_zones(
    components: list[Component],
    flows: list[DataFlow],
) -> list[Component]:
    """Assign trust zones to components based on their properties."""
    result = []
    for comp in components:
        zone = _infer_zone(comp)
        result.append(comp.model_copy(update={"trust_zone": zone}))
    return result


def _infer_zone(comp: Component) -> TrustZone:
    """Infer the trust zone for a single component."""
    name_lower = comp.name.lower()

    # Internet/external always go to PUBLIC_INTERNET
    if any(term in name_lower for term in ("internet", "external", "client", "public", "cdn")):
        return TrustZone.PUBLIC_INTERNET

    # Databases and caches always go to Database Tier
    if comp.type in (ComponentType.DATABASE, ComponentType.CACHE):
        return TrustZone.DATABASE_TIER

    # Storage
    if comp.type == ComponentType.STORAGE:
        return TrustZone.STORAGE_TIER

    # Messaging
    if comp.type == ComponentType.QUEUE:
        return TrustZone.MESSAGING_TIER

    # Observability
    if comp.type == ComponentType.OBSERVABILITY:
        return TrustZone.OBSERVABILITY_TIER

    # Third-party services
    if comp.type == ComponentType.THIRD_PARTY:
        return TrustZone.THIRD_PARTY

    # API Gateways and Load Balancers face the internet and sit in the DMZ
    if comp.type in (ComponentType.API_GATEWAY, ComponentType.LOAD_BALANCER):
        return TrustZone.DMZ

    # Payment-related services -> PCI Zone
    if any(term in name_lower for term in ("payment", "billing", "stripe", "card")):
        has_payment_env = any(
            any(term in k.lower() for term in ("stripe", "payment", "card"))
            for k in comp.environment
        )
        if has_payment_env:
            return TrustZone.PCI_ZONE

    # Admin services
    if any(term in name_lower for term in ("admin", "backoffice", "dashboard")):
        return TrustZone.ADMIN_ZONE

    return TrustZone.INTERNAL_SERVICES


def _enrich_flows(
    flows: list[DataFlow],
    components: dict[str, Component],
) -> list[DataFlow]:
    """Enrich data flows with protocol and security info."""
    enriched = []
    for flow in flows:
        updates: dict = {}

        src = components.get(flow.source)
        dst = components.get(flow.destination)

        # Infer encryption from protocol
        if flow.protocol in ("https", "tls", "ssl", "grpcs"):
            updates["is_encrypted"] = True
        elif flow.protocol in ("http", "tcp", "grpc"):
            updates["is_encrypted"] = False

        # Infer data classification from destination type
        if dst and dst.type == ComponentType.DATABASE:
            if not flow.data_classification:
                updates["data_classification"] = "persistent_data"
        if dst and dst.type == ComponentType.CACHE:
            if not flow.data_classification:
                updates["data_classification"] = "session_data"

        # Check for auth-related flows
        if src and dst:
            src_name = src.name.lower()
            dst_name = dst.name.lower()
            if "auth" in src_name or "auth" in dst_name:
                updates["data_classification"] = updates.get(
                    "data_classification", "authentication_data"
                )

        if updates:
            enriched.append(flow.model_copy(update=updates))
        else:
            enriched.append(flow)

    return enriched


def _infer_boundaries(
    components: list[Component],
    flows: list[DataFlow],
    existing: list[TrustBoundary],
) -> list[TrustBoundary]:
    """Infer trust boundaries from component zones and data flows."""
    boundaries = list(existing)
    existing_names = {b.name for b in boundaries}

    # Group components by zone
    zones: dict[TrustZone, list[str]] = {}
    comp_zones: dict[str, TrustZone] = {}
    for comp in components:
        zones.setdefault(comp.trust_zone, []).append(comp.name)
        comp_zones[comp.name] = comp.trust_zone

    # Find boundary-crossing flows
    boundary_pairs: dict[tuple[TrustZone, TrustZone], list[str]] = {}
    for flow in flows:
        src_zone = comp_zones.get(flow.source)
        dst_zone = comp_zones.get(flow.destination)

        if src_zone and dst_zone and src_zone != dst_zone:
            pair = (src_zone, dst_zone)
            if pair not in boundary_pairs:
                boundary_pairs[pair] = []
            boundary_pairs[pair].append(flow.source)
            boundary_pairs[pair].append(flow.destination)

    # Create boundary objects
    for (zone_from, zone_to), comps in boundary_pairs.items():
        name = f"{zone_from.value} → {zone_to.value}"
        if name not in existing_names:
            unique_comps = list(set(comps))
            boundaries.append(
                TrustBoundary(
                    name=name,
                    zone_from=zone_from,
                    zone_to=zone_to,
                    components=unique_comps,
                    description=f"Data crosses from {zone_from.value} to {zone_to.value}",
                )
            )
            existing_names.add(name)

    return boundaries


def _discover_assets(
    components: list[Component],
    existing: list[Asset],
) -> list[Asset]:
    """Discover sensitive assets from component environment variables."""
    assets = list(existing)
    existing_keys = {(a.name, a.location) for a in assets}

    for comp in components:
        for env_key, env_value in comp.environment.items():
            for pattern, asset_type, description in _SENSITIVE_ENV_PATTERNS:
                if pattern.search(env_key):
                    asset_name = f"{env_key.lower()}"
                    if (asset_name, comp.name) not in existing_keys:
                        assets.append(
                            Asset(
                                name=asset_name,
                                type=asset_type,
                                location=comp.name,
                                classification="sensitive",
                                description=f"{description} found in {comp.name} environment",
                            )
                        )
                        existing_keys.add((asset_name, comp.name))
                    break  # one match per env var is enough

    return assets

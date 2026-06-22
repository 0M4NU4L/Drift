"""Core data models for Drift.

All Pydantic v2 models that form the data contracts across
parsers, engines, reports, and the CLI.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ComponentType(str, Enum):
    """Classification of architectural components."""
    API_GATEWAY = "api_gateway"
    SERVICE = "service"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    SERVERLESS = "serverless"
    THIRD_PARTY = "third_party"
    STORAGE = "storage"
    LOAD_BALANCER = "load_balancer"
    CDN = "cdn"
    PROXY = "proxy"
    UNKNOWN = "unknown"


class TrustZone(str, Enum):
    """Trust zones for boundary detection."""
    PUBLIC_INTERNET = "Public Internet"
    DMZ = "DMZ"
    INTERNAL_SERVICES = "Internal Services"
    DATABASE_TIER = "Database Tier"
    THIRD_PARTY = "Third-Party APIs"
    ADMIN_ZONE = "Admin Zone"
    PCI_ZONE = "PCI Zone"


class AssetType(str, Enum):
    """Sensitive asset classifications."""
    PII = "pii"
    CREDENTIALS = "credentials"
    TOKENS = "tokens"
    CARD_DATA = "card_data"
    SESSION_DATA = "session_data"
    ENCRYPTION_KEYS = "encryption_keys"
    API_KEYS = "api_keys"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class StrideCategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


# ---------------------------------------------------------------------------
# Core Models
# ---------------------------------------------------------------------------

class Component(BaseModel):
    """An architectural component (service, database, gateway, etc.)."""
    name: str
    type: ComponentType = ComponentType.UNKNOWN
    properties: dict = Field(default_factory=dict)
    protocols: list[str] = Field(default_factory=list)
    environment: dict = Field(default_factory=dict)
    exposed_ports: list[int] = Field(default_factory=list)
    trust_zone: TrustZone = TrustZone.INTERNAL_SERVICES
    source: str = ""
    image: str = ""

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Component):
            return self.name == other.name
        return NotImplemented


class DataFlow(BaseModel):
    """A data flow between two components."""
    source: str
    destination: str
    protocol: str = "unknown"
    port: Optional[int] = None
    data_classification: str = ""
    is_authenticated: bool = False
    is_encrypted: bool = False
    description: str = ""

    @property
    def label(self) -> str:
        return f"{self.source} → {self.destination}"


class TrustBoundary(BaseModel):
    """A trust boundary between two zones."""
    name: str
    zone_from: TrustZone
    zone_to: TrustZone
    components: list[str] = Field(default_factory=list)
    description: str = ""

    @property
    def label(self) -> str:
        return f"{self.zone_from.value} → {self.zone_to.value}"


class Asset(BaseModel):
    """A sensitive asset discovered in the architecture."""
    name: str
    type: AssetType
    location: str  # component name
    classification: str = ""
    description: str = ""


from pydantic import BaseModel, Field, model_validator
from typing import Optional, Any

class Threat(BaseModel):
    """A STRIDE threat with evidence and explainability."""
    id: str = ""
    stride_category: StrideCategory
    title: str
    severity: Severity
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 1.0
    boundary: str  # "Zone A -> Zone B"
    explanation: str = ""
    mitigation: str = ""
    affected_components: list[str] = Field(default_factory=list)
    likelihood: int = Field(default=3, ge=1, le=5)
    impact: int = Field(default=3, ge=1, le=5)

    @model_validator(mode='before')
    @classmethod
    def _migrate_evidence(cls, data: Any) -> Any:
        """Backward compatibility for drift.lock files with string evidence."""
        if isinstance(data, dict):
            evidence = data.get('evidence')
            if isinstance(evidence, str):
                data['evidence'] = [evidence]
        return data

    def model_post_init(self, __context: object) -> None:
        """Auto-generate threat ID from content if not provided."""
        if not self.id:
            # We use the title, category, and boundary for deterministic ID.
            content = f"{self.stride_category.value}:{self.title}:{self.boundary}"
            self.id = hashlib.sha256(content.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Aggregate Models
# ---------------------------------------------------------------------------

class Architecture(BaseModel):
    """Complete architecture representation."""
    components: list[Component] = Field(default_factory=list)
    flows: list[DataFlow] = Field(default_factory=list)
    boundaries: list[TrustBoundary] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)

    def get_component(self, name: str) -> Optional[Component]:
        """Find a component by name."""
        for c in self.components:
            if c.name == name:
                return c
        return None

    def merge(self, other: Architecture) -> Architecture:
        """Merge another architecture into this one, deduplicating components."""
        existing_names = {c.name for c in self.components}
        new_components = [c for c in other.components if c.name not in existing_names]

        existing_flows = {(f.source, f.destination) for f in self.flows}
        new_flows = [
            f for f in other.flows
            if (f.source, f.destination) not in existing_flows
        ]

        existing_boundaries = {b.name for b in self.boundaries}
        new_boundaries = [b for b in other.boundaries if b.name not in existing_boundaries]

        existing_assets = {(a.name, a.location) for a in self.assets}
        new_assets = [
            a for a in other.assets
            if (a.name, a.location) not in existing_assets
        ]

        return Architecture(
            components=self.components + new_components,
            flows=self.flows + new_flows,
            boundaries=self.boundaries + new_boundaries,
            assets=self.assets + new_assets,
            metadata={**self.metadata, **other.metadata},
        )


class ThreatDelta(BaseModel):
    """Difference between current threats and baseline."""
    new_threats: list[Threat] = Field(default_factory=list)
    mitigated_threats: list[Threat] = Field(default_factory=list)
    new_components: list[str] = Field(default_factory=list)
    removed_components: list[str] = Field(default_factory=list)
    new_boundaries: list[str] = Field(default_factory=list)
    removed_boundaries: list[str] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_threats
            or self.mitigated_threats
            or self.new_components
            or self.removed_components
            or self.new_boundaries
            or self.removed_boundaries
        )


class Baseline(BaseModel):
    """Snapshot saved to drift.lock."""
    version: str = "1.0.0"
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    architecture: Architecture = Field(default_factory=Architecture)
    threats: list[Threat] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Complete output of a Drift analysis run."""
    architecture: Architecture
    threats: list[Threat] = Field(default_factory=list)
    delta: Optional[ThreatDelta] = None
    ai_enhanced: bool = False

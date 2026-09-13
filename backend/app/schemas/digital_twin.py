"""Digital Twin schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import (
    AssetLayer,
    AssetStatus,
    AssetType,
    Criticality,
    Exploitability,
    RelationshipType,
    Severity,
    SimulationState,
    TrustLevel,
    VulnerabilityStatus,
)


class TwinServiceNode(BaseModel):
    service_name: str
    protocol: Optional[str] = None
    port: Optional[int] = None


class TwinVulnerabilityNode(BaseModel):
    vulnerability_id: str
    identifier: str
    name: str
    severity: Severity
    cvss_score: float
    exploitability: Exploitability
    status: VulnerabilityStatus
    is_synthetic: bool


class TwinAssetNode(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: AssetType
    layer: AssetLayer
    description: Optional[str] = None
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: Criticality
    trust_level: TrustLevel
    status: AssetStatus
    services: list[TwinServiceNode] = Field(default_factory=list)
    vulnerabilities: list[TwinVulnerabilityNode] = Field(default_factory=list)
    vulnerability_count: int = 0
    open_vulnerability_count: int = 0
    security_state: str = "UNKNOWN"
    simulation_state: SimulationState = SimulationState.NORMAL
    exposure: str = "UNKNOWN"


class TwinRelationshipEdge(BaseModel):
    relationship_id: str
    source_asset_id: str
    target_asset_id: str
    source_name: str
    target_name: str
    relationship_type: RelationshipType
    protocol: Optional[str] = None
    port: Optional[int] = None
    trust_level: TrustLevel
    description: Optional[str] = None


class TwinTopologyLayer(BaseModel):
    layer: AssetLayer
    asset_ids: list[str]


class TwinTopology(BaseModel):
    nodes: list[TwinAssetNode]
    edges: list[TwinRelationshipEdge]
    layers: list[TwinTopologyLayer]


class DigitalTwinSnapshot(BaseModel):
    """Full virtual representation of the Smart Hospital infrastructure."""

    generated_at: datetime
    environment: str = "Smart Hospital Cloud-IoT (Synthetic)"
    asset_count: int
    relationship_count: int
    vulnerability_count: int
    critical_asset_count: int
    assets: list[TwinAssetNode]
    relationships: list[TwinRelationshipEdge]
    topology: TwinTopology
    notes: list[str] = Field(default_factory=list)

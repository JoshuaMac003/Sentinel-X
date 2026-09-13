"""Attack graph API schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import AssetType, AttackStage, Criticality, Exploitability, RiskBand


class AttackGraphNode(BaseModel):
    id: str
    asset_name: str
    asset_type: AssetType
    criticality: Criticality
    compromise_state: str = "UNCOMPROMISED"
    layer: str
    open_vulnerability_count: int = 0


class AttackGraphEdge(BaseModel):
    source: str
    target: str
    relationship_id: str
    relationship_type: str
    trust_level: str
    vulnerability_id: Optional[str] = None
    vulnerability_identifier: Optional[str] = None
    exploitability: Optional[Exploitability] = None
    prerequisite: str = "network_reachability"
    attack_stage: AttackStage = AttackStage.LATERAL_MOVEMENT
    edge_risk: float = Field(ge=0.0, le=100.0)


class AttackGraphResponse(BaseModel):
    node_count: int
    edge_count: int
    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]
    notes: list[str] = Field(default_factory=list)


class AttackPathHop(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: AssetType


class AttackPath(BaseModel):
    path_id: str
    source_asset_id: str
    source_name: str
    target_asset_id: str
    target_name: str
    hops: list[AttackPathHop]
    asset_ids: list[str]
    stage_count: int
    length: int
    vulnerabilities_on_path: list[str] = Field(default_factory=list)
    scenario_label: Optional[str] = None
    explanation: str
    risk_score: Optional[float] = None
    risk_band: Optional[RiskBand] = None


class AttackPathsResponse(BaseModel):
    path_count: int
    paths: list[AttackPath]
    notes: list[str] = Field(default_factory=list)

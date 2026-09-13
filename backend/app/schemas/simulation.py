"""Review 2 simulation and security-mapping schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import (
    AttackType,
    RiskBand,
    SimulationAction,
    SimulationResult,
    SimulationState,
)
from app.schemas.risk import RiskFactor


class ScenarioRead(BaseModel):
    scenario_id: str
    scenario_code: str
    scenario_name: str
    description: Optional[str] = None
    source_asset_id: str
    source_name: str
    target_asset_id: str
    target_name: str
    attack_type: AttackType
    enabled: bool
    preferred_waypoints: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class SimulationCreate(BaseModel):
    scenario_id: Optional[str] = None
    source_asset_id: Optional[str] = None
    target_asset_id: Optional[str] = None


class SimulationEventRead(BaseModel):
    event_id: str
    simulation_id: str
    step_number: int
    source_asset_id: Optional[str] = None
    source_name: Optional[str] = None
    target_asset_id: Optional[str] = None
    target_name: Optional[str] = None
    action: SimulationAction
    reason: str
    vulnerability_identifier: Optional[str] = None
    previous_state: SimulationState
    new_state: SimulationState
    success: bool
    risk_impact: float
    timestamp: datetime


class BlastRadiusRead(BaseModel):
    origin_asset_id: str
    origin_name: str
    reachable_asset_count: int
    vulnerable_reachable_count: int
    critical_assets_reachable: int
    sensitive_data_assets_reached: int
    maximum_propagation_depth: int
    impact_score: float
    reachable_asset_ids: list[str] = Field(default_factory=list)
    explanation: str


class SimulationImpactRead(BaseModel):
    impact_id: str
    simulation_id: str
    propagation_depth: int
    compromised_count: int
    reachable_count: int
    vulnerable_reachable_count: int
    critical_reached_count: int
    sensitive_data_reached_count: int
    target_reached: bool
    maximum_propagation_depth: int
    impact_score: float
    blast_radius_score: float
    blast_radius: Optional[BlastRadiusRead] = None
    factors: list[RiskFactor] = Field(default_factory=list)
    explanation: Optional[str] = None
    propagation_path: list[str] = Field(default_factory=list)
    compromised_asset_ids: list[str] = Field(default_factory=list)
    compromised_asset_names: list[str] = Field(default_factory=list)


class RiskComparisonRead(BaseModel):
    simulation_id: str
    baseline_risk: float
    baseline_band: RiskBand
    simulation_risk: float
    simulation_band: RiskBand
    risk_change: float
    factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str
    model_version: str = "simulation-v1"
    notes: list[str] = Field(default_factory=list)


class SimulationSummary(BaseModel):
    simulation_id: str
    scenario_id: Optional[str] = None
    scenario_code: Optional[str] = None
    scenario_name: Optional[str] = None
    result: SimulationResult
    target_reached: bool
    step_count: int
    compromised_count: int
    impact_score: Optional[float] = None
    baseline_risk: Optional[float] = None
    simulation_risk: Optional[float] = None
    risk_change: Optional[float] = None
    created_at: datetime
    block_reason: Optional[str] = None


class SimulationRead(BaseModel):
    simulation_id: str
    scenario: Optional[ScenarioRead] = None
    result: SimulationResult
    target_reached: bool
    block_reason: Optional[str] = None
    path_asset_ids: list[str] = Field(default_factory=list)
    path_display: str = ""
    compromised_asset_ids: list[str] = Field(default_factory=list)
    isolated_asset_ids: list[str] = Field(default_factory=list)
    events: list[SimulationEventRead] = Field(default_factory=list)
    impact: Optional[SimulationImpactRead] = None
    risk_comparison: Optional[RiskComparisonRead] = None
    explanation: Optional[str] = None
    model_version: str
    created_at: datetime


class AssetSecurityProfile(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    layer: str
    criticality: int
    trust_level: str
    status: str
    security_state: str
    simulation_state: SimulationState = SimulationState.NORMAL
    services: list[str] = Field(default_factory=list)
    relationship_count: int = 0
    outbound_targets: list[str] = Field(default_factory=list)
    inbound_sources: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    is_vulnerable: bool
    is_critical: bool
    reachable_asset_ids: list[str] = Field(default_factory=list)
    downstream_asset_ids: list[str] = Field(default_factory=list)
    vulnerable_reachable_ids: list[str] = Field(default_factory=list)
    critical_reachable_ids: list[str] = Field(default_factory=list)
    sensitive_reachable_ids: list[str] = Field(default_factory=list)
    blast_radius: BlastRadiusRead
    potential_impact: str


class VulnerabilityContext(BaseModel):
    vulnerability_id: str
    identifier: str
    name: str
    asset_id: str
    asset_name: str
    severity: str
    cvss_score: float
    exploitability: str
    status: str
    remediation: Optional[str] = None
    is_synthetic: bool
    simulation_relevance: str
    related_path_count: int = 0
    related_path_summaries: list[str] = Field(default_factory=list)

"""Risk API schemas."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import RiskBand


class RiskFactor(BaseModel):
    name: str
    value: float = Field(description="Normalized 0–1 contribution input")
    weight: float
    weighted_contribution: float = Field(
        description="value * weight on a 0–1 scale before *100"
    )
    contribution: float = Field(
        default=0.0,
        description="Points contributed toward the 0–100 score (weighted_contribution * 100)",
    )
    detail: str


class AssetRisk(BaseModel):
    asset_id: str
    asset_name: str
    risk_score: float
    risk_band: RiskBand
    factors: list[RiskFactor]
    explanation: str


class PathRisk(BaseModel):
    path_id: str
    source_name: str
    target_name: str
    path_display: str
    stage_count: int
    risk_score: float
    risk_band: RiskBand
    factors: list[RiskFactor]
    explanation: str
    scenario_label: Optional[str] = None


class RiskOverview(BaseModel):
    overall_risk_score: float
    overall_risk_band: RiskBand
    model_version: str = "baseline-v1"
    asset_count: int
    assessed_assets: int
    path_count: int
    high_or_critical_assets: int
    high_or_critical_paths: int
    factors_summary: list[RiskFactor]
    explanation: str
    high_risk_assets: list[AssetRisk]
    high_risk_paths: list[PathRisk]
    distribution: dict[str, int]
    notes: list[str] = Field(default_factory=list)

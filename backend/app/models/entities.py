"""ORM models for SENTINEL-X Review 1."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AssetLayer,
    AssetStatus,
    AssetType,
    AttackStage,
    AttackType,
    Criticality,
    Exploitability,
    PlatformRole,
    RelationshipType,
    RiskBand,
    Severity,
    SimulationAction,
    SimulationResult,
    SimulationState,
    TrustLevel,
    VulnerabilityStatus,
)
from app.database.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), nullable=False, index=True)
    layer: Mapped[AssetLayer] = mapped_column(Enum(AssetLayer), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    operating_system: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality), nullable=False, default=Criticality.MEDIUM
    )
    trust_level: Mapped[TrustLevel] = mapped_column(
        Enum(TrustLevel), nullable=False, default=TrustLevel.MEDIUM
    )
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus), nullable=False, default=AssetStatus.ACTIVE
    )
    # Sparse extensibility only — structured fields remain relational.
    metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    services: Mapped[list[AssetService]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list[Vulnerability]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    outbound_relationships: Mapped[list[AssetRelationship]] = relationship(
        back_populates="source_asset",
        foreign_keys="AssetRelationship.source_asset_id",
        cascade="all, delete-orphan",
    )
    inbound_relationships: Mapped[list[AssetRelationship]] = relationship(
        back_populates="target_asset",
        foreign_keys="AssetRelationship.target_asset_id",
        cascade="all, delete-orphan",
    )


class AssetService(Base, TimestampMixin):
    __tablename__ = "asset_services"
    __table_args__ = (
        UniqueConstraint("asset_id", "service_name", "port", name="uq_asset_service"),
    )

    service_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    service_name: Mapped[str] = mapped_column(String(128), nullable=False)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="services")


class AssetRelationship(Base, TimestampMixin):
    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            "protocol",
            "port",
            name="uq_relationship_edge",
        ),
    )

    relationship_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_type: Mapped[RelationshipType] = mapped_column(
        Enum(RelationshipType), nullable=False
    )
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    trust_level: Mapped[TrustLevel] = mapped_column(
        Enum(TrustLevel), nullable=False, default=TrustLevel.MEDIUM
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    source_asset: Mapped[Asset] = relationship(
        back_populates="outbound_relationships", foreign_keys=[source_asset_id]
    )
    target_asset: Mapped[Asset] = relationship(
        back_populates="inbound_relationships", foreign_keys=[target_asset_id]
    )


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    vulnerability_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Synthetic demonstration identifiers (e.g. SYN-AUTH-001). Never invent CVE IDs.
    identifier: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False)
    exploitability: Mapped[Exploitability] = mapped_column(Enum(Exploitability), nullable=False)
    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus), nullable=False, default=VulnerabilityStatus.OPEN
    )
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    asset: Mapped[Asset] = relationship(back_populates="vulnerabilities")


class PlatformUser(Base, TimestampMixin):
    """Platform operators / demo analysts — not hospital patient records."""

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[PlatformRole] = mapped_column(
        Enum(PlatformRole), nullable=False, default=PlatformRole.ANALYST
    )
    email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class AttackPathRecord(Base, TimestampMixin):
    """Persisted analytical attack-path results (foundation for later simulation)."""

    __tablename__ = "attack_paths"

    attack_path_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    path_nodes_json: Mapped[str] = mapped_column(Text, nullable=False)
    stage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attack_stage: Mapped[AttackStage] = mapped_column(
        Enum(AttackStage), nullable=False, default=AttackStage.LATERAL_MOVEMENT
    )
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_band: Mapped[Optional[RiskBand]] = mapped_column(Enum(RiskBand), nullable=True)
    scenario_label: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class RiskAssessment(Base, TimestampMixin):
    """Baseline risk assessments for assets or attack paths."""

    __tablename__ = "risk_assessments"

    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ASSET | PATH | OVERVIEW
    subject_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_band: Mapped[RiskBand] = mapped_column(Enum(RiskBand), nullable=False)
    factors_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False, default="baseline-v1")


class AttackScenario(Base, TimestampMixin):
    """Formal analytical attack scenario (synthetic, non-exploitative)."""

    __tablename__ = "attack_scenarios"

    scenario_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scenario_code: Mapped[str] = mapped_column(String(8), nullable=False, unique=True, index=True)
    scenario_name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_type: Mapped[AttackType] = mapped_column(Enum(AttackType), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    preferred_waypoints_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    simulations: Mapped[list["SimulationRun"]] = relationship(
        back_populates="scenario", cascade="all, delete-orphan"
    )


class SimulationRun(Base, TimestampMixin):
    """One controlled Digital Twin simulation run. Does not mutate baseline assets."""

    __tablename__ = "simulations"

    simulation_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scenario_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("attack_scenarios.scenario_id", ondelete="SET NULL"), nullable=True, index=True
    )
    result: Mapped[SimulationResult] = mapped_column(Enum(SimulationResult), nullable=False)
    target_reached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    block_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    path_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compromised_assets_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    isolated_assets_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    baseline_risk: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    simulation_risk: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_change: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False, default="simulation-v1")

    scenario: Mapped[Optional[AttackScenario]] = relationship(back_populates="simulations")
    events: Mapped[list["SimulationEvent"]] = relationship(
        back_populates="simulation", cascade="all, delete-orphan", order_by="SimulationEvent.step_number"
    )
    impact: Mapped[Optional["SimulationImpact"]] = relationship(
        back_populates="simulation", cascade="all, delete-orphan", uselist=False
    )


class SimulationEvent(Base, TimestampMixin):
    __tablename__ = "simulation_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    simulation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulations.simulation_id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    source_asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    target_asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action: Mapped[SimulationAction] = mapped_column(Enum(SimulationAction), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    vulnerability_identifier: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    previous_state: Mapped[SimulationState] = mapped_column(
        Enum(SimulationState), nullable=False, default=SimulationState.NORMAL
    )
    new_state: Mapped[SimulationState] = mapped_column(
        Enum(SimulationState), nullable=False, default=SimulationState.NORMAL
    )
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_impact: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    simulation: Mapped[SimulationRun] = relationship(back_populates="events")


class SimulationImpact(Base, TimestampMixin):
    __tablename__ = "simulation_impacts"

    impact_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    simulation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("simulations.simulation_id", ondelete="CASCADE"), nullable=False, unique=True
    )
    propagation_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    compromised_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reachable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerable_reachable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_reached_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sensitive_data_reached_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    target_reached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    maximum_propagation_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    impact_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    blast_radius_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    factors_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    simulation: Mapped[SimulationRun] = relationship(back_populates="impact")

"""Digital Twin service — builds a live virtual model from database state."""

from __future__ import annotations

from datetime import datetime, timezone
import json

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.enums import (
    AssetLayer,
    AssetStatus,
    Criticality,
    SimulationState,
    VulnerabilityStatus,
)
from app.models import Asset, AssetRelationship, SimulationRun
from app.schemas.digital_twin import (
    DigitalTwinSnapshot,
    TwinAssetNode,
    TwinRelationshipEdge,
    TwinServiceNode,
    TwinTopology,
    TwinTopologyLayer,
    TwinVulnerabilityNode,
)

LAYER_ORDER = [
    AssetLayer.IOT,
    AssetLayer.EDGE,
    AssetLayer.NETWORK,
    AssetLayer.CLOUD,
    AssetLayer.APPLICATION,
    AssetLayer.DATA,
    AssetLayer.USER,
]


def _security_state(asset: Asset) -> str:
    if asset.status == AssetStatus.COMPROMISED:
        return "COMPROMISED"
    open_vulns = [
        v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN
    ]
    if not open_vulns:
        return "HARDENED"
    critical_open = [v for v in open_vulns if v.severity.value in {"HIGH", "CRITICAL"}]
    if critical_open:
        return "AT_RISK"
    return "DEGRADED"


def _exposure(asset: Asset) -> str:
    open_vulns = [v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN]
    if not open_vulns:
        return "LOW"
    high = any(v.severity.value in {"HIGH", "CRITICAL"} for v in open_vulns)
    if high and int(asset.criticality) >= 4:
        return "HIGH"
    if high or int(asset.criticality) >= 4:
        return "MEDIUM"
    return "LOW"


class DigitalTwinService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _load_assets(self) -> list[Asset]:
        stmt = (
            select(Asset)
            .options(
                selectinload(Asset.services),
                selectinload(Asset.vulnerabilities),
            )
            .order_by(Asset.asset_name.asc())
        )
        return list(self.db.scalars(stmt).all())

    def _load_relationships(self) -> list[AssetRelationship]:
        stmt = select(AssetRelationship).order_by(AssetRelationship.created_at.asc())
        return list(self.db.scalars(stmt).all())

    def build_snapshot(self, simulation_id: str | None = None) -> DigitalTwinSnapshot:
        assets = self._load_assets()
        relationships = self._load_relationships()
        asset_by_id = {a.asset_id: a for a in assets}

        overlay: dict[str, SimulationState] = {}
        if simulation_id:
            run = self.db.get(SimulationRun, simulation_id)
            if run is not None:
                for aid in json.loads(run.compromised_assets_json or "[]"):
                    overlay[aid] = SimulationState.COMPROMISED
                for aid in json.loads(run.isolated_assets_json or "[]"):
                    overlay[aid] = SimulationState.ISOLATED

        twin_assets: list[TwinAssetNode] = []
        for asset in assets:
            vulns = [
                TwinVulnerabilityNode(
                    vulnerability_id=v.vulnerability_id,
                    identifier=v.identifier,
                    name=v.name,
                    severity=v.severity,
                    cvss_score=v.cvss_score,
                    exploitability=v.exploitability,
                    status=v.status,
                    is_synthetic=v.is_synthetic,
                )
                for v in asset.vulnerabilities
            ]
            twin_assets.append(
                TwinAssetNode(
                    asset_id=asset.asset_id,
                    asset_name=asset.asset_name,
                    asset_type=asset.asset_type,
                    layer=asset.layer,
                    description=asset.description,
                    ip_address=asset.ip_address,
                    operating_system=asset.operating_system,
                    criticality=asset.criticality,
                    trust_level=asset.trust_level,
                    status=asset.status,
                    services=[
                        TwinServiceNode(
                            service_name=s.service_name,
                            protocol=s.protocol,
                            port=s.port,
                        )
                        for s in asset.services
                    ],
                    vulnerabilities=vulns,
                    vulnerability_count=len(vulns),
                    open_vulnerability_count=sum(
                        1 for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN
                    ),
                    security_state=_security_state(asset),
                    simulation_state=overlay.get(asset.asset_id, SimulationState.NORMAL),
                    exposure=_exposure(asset),
                )
            )

        twin_edges: list[TwinRelationshipEdge] = []
        for rel in relationships:
            source = asset_by_id.get(rel.source_asset_id)
            target = asset_by_id.get(rel.target_asset_id)
            if source is None or target is None:
                continue
            twin_edges.append(
                TwinRelationshipEdge(
                    relationship_id=rel.relationship_id,
                    source_asset_id=rel.source_asset_id,
                    target_asset_id=rel.target_asset_id,
                    source_name=source.asset_name,
                    target_name=target.asset_name,
                    relationship_type=rel.relationship_type,
                    protocol=rel.protocol,
                    port=rel.port,
                    trust_level=rel.trust_level,
                    description=rel.description,
                )
            )

        layers: list[TwinTopologyLayer] = []
        for layer in LAYER_ORDER:
            ids = [a.asset_id for a in twin_assets if a.layer == layer]
            if ids:
                layers.append(TwinTopologyLayer(layer=layer, asset_ids=ids))

        topology = TwinTopology(nodes=twin_assets, edges=twin_edges, layers=layers)
        critical_count = sum(
            1 for a in twin_assets if a.criticality == Criticality.CRITICAL
        )
        vuln_count = sum(a.vulnerability_count for a in twin_assets)

        return DigitalTwinSnapshot(
            generated_at=datetime.now(timezone.utc),
            asset_count=len(twin_assets),
            relationship_count=len(twin_edges),
            vulnerability_count=vuln_count,
            critical_asset_count=critical_count,
            assets=twin_assets,
            relationships=twin_edges,
            topology=topology,
            notes=[
                "Digital Twin is generated dynamically from the current database state.",
                "All assets and vulnerabilities are synthetic demonstration data.",
                "Security state is derived from asset status and open vulnerabilities.",
                "simulation_state is an isolated overlay and does not mutate baseline assets.",
            ],
        )

    def build_topology(self, simulation_id: str | None = None) -> TwinTopology:
        return self.build_snapshot(simulation_id=simulation_id).topology

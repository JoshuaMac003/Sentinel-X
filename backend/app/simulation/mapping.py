"""Asset security mapping and analytical blast-radius (Review 2)."""

from __future__ import annotations

import json
from typing import Optional

import networkx as nx
from sqlalchemy.orm import Session

from app.attack_graph import AttackGraphEngine
from app.core.enums import AssetLayer, AssetType, Criticality, SimulationState, VulnerabilityStatus
from app.digital_twin import DigitalTwinService
from app.models import SimulationRun
from app.schemas.digital_twin import TwinAssetNode
from app.schemas.simulation import AssetSecurityProfile, BlastRadiusRead, VulnerabilityContext


SENSITIVE_TYPES = {AssetType.DATABASE}
SENSITIVE_LAYERS = {AssetLayer.DATA}


def _is_sensitive(asset: TwinAssetNode) -> bool:
    return asset.asset_type in SENSITIVE_TYPES or asset.layer in SENSITIVE_LAYERS


def _is_vulnerable(asset: TwinAssetNode) -> bool:
    return any(v.status == VulnerabilityStatus.OPEN for v in asset.vulnerabilities)


def _best_open_identifier(asset: TwinAssetNode) -> Optional[str]:
    open_v = [v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN]
    if not open_v:
        return None
    open_v.sort(key=lambda v: v.cvss_score, reverse=True)
    return open_v[0].identifier


class SecurityMappingService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.twin = DigitalTwinService(db)
        self.graph_engine = AttackGraphEngine(db)

    def blast_radius(self, origin_asset_id: str) -> BlastRadiusRead:
        snapshot = self.twin.build_snapshot()
        assets = {a.asset_id: a for a in snapshot.assets}
        origin = assets.get(origin_asset_id)
        if origin is None:
            raise KeyError(origin_asset_id)

        nx_graph, _ = self.graph_engine._build_graph(snapshot)  # analytical descendants
        reachable = {origin_asset_id}
        if origin_asset_id in nx_graph:
            reachable |= set(nx.descendants(nx_graph, origin_asset_id))

        depths = []
        for aid in reachable:
            if aid == origin_asset_id:
                depths.append(0)
                continue
            try:
                depths.append(nx.shortest_path_length(nx_graph, origin_asset_id, aid))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        max_depth = max(depths) if depths else 0

        vulnerable = [aid for aid in reachable if _is_vulnerable(assets[aid])]
        critical = [
            aid for aid in reachable if assets[aid].criticality == Criticality.CRITICAL
        ]
        sensitive = [aid for aid in reachable if _is_sensitive(assets[aid])]
        total = max(1, snapshot.asset_count)
        score = round(
            min(
                100.0,
                100.0
                * (
                    0.35 * (len(reachable) / total)
                    + 0.25 * (len(vulnerable) / total)
                    + 0.25 * (len(critical) / max(1, sum(1 for a in assets.values() if a.criticality == Criticality.CRITICAL)))
                    + 0.15 * min(1.0, max_depth / 6.0)
                ),
            ),
            2,
        )
        return BlastRadiusRead(
            origin_asset_id=origin_asset_id,
            origin_name=origin.asset_name,
            reachable_asset_count=len(reachable),
            vulnerable_reachable_count=len(vulnerable),
            critical_assets_reachable=len(critical),
            sensitive_data_assets_reached=len(sensitive),
            maximum_propagation_depth=max_depth,
            impact_score=score,
            reachable_asset_ids=sorted(reachable),
            explanation=(
                f"Analytical blast radius from {origin.asset_name}: {len(reachable)} reachable "
                f"asset(s), {len(vulnerable)} vulnerable, {len(critical)} critical, "
                f"{len(sensitive)} sensitive-data, max depth {max_depth}. "
                "This is a Digital Twin graph metric, not a validated real-world blast-radius standard."
            ),
        )

    def profile(self, asset_id: str, simulation_id: Optional[str] = None) -> AssetSecurityProfile:
        snapshot = self.twin.build_snapshot(simulation_id=simulation_id)
        assets = {a.asset_id: a for a in snapshot.assets}
        asset = assets.get(asset_id)
        if asset is None:
            raise KeyError(asset_id)

        outbound = [e.target_name for e in snapshot.relationships if e.source_asset_id == asset_id]
        inbound = [e.source_name for e in snapshot.relationships if e.target_asset_id == asset_id]
        radius = self.blast_radius(asset_id)
        reachable_ids = [i for i in radius.reachable_asset_ids if i != asset_id]
        vulnerable_ids = [i for i in reachable_ids if _is_vulnerable(assets[i])]
        critical_ids = [
            i for i in reachable_ids if assets[i].criticality == Criticality.CRITICAL
        ]
        sensitive_ids = [i for i in reachable_ids if _is_sensitive(assets[i])]

        sim_state = asset.simulation_state
        if simulation_id:
            run = self.db.get(SimulationRun, simulation_id)
            if run and run.compromised_assets_json:
                compromised = set(json.loads(run.compromised_assets_json))
                if asset_id in compromised:
                    sim_state = SimulationState.COMPROMISED

        impact = (
            f"{asset.asset_name} can analytically reach {len(reachable_ids)} downstream asset(s) "
            f"({len(critical_ids)} critical, {len(sensitive_ids)} sensitive-data)."
        )
        return AssetSecurityProfile(
            asset_id=asset.asset_id,
            asset_name=asset.asset_name,
            asset_type=asset.asset_type.value,
            layer=asset.layer.value,
            criticality=int(asset.criticality),
            trust_level=asset.trust_level.value,
            status=asset.status.value,
            security_state=asset.security_state,
            simulation_state=sim_state,
            services=[s.service_name for s in asset.services],
            relationship_count=len(outbound) + len(inbound),
            outbound_targets=outbound,
            inbound_sources=inbound,
            vulnerabilities=[v.identifier for v in asset.vulnerabilities],
            is_vulnerable=_is_vulnerable(asset),
            is_critical=asset.criticality == Criticality.CRITICAL,
            reachable_asset_ids=reachable_ids,
            downstream_asset_ids=outbound,
            vulnerable_reachable_ids=vulnerable_ids,
            critical_reachable_ids=critical_ids,
            sensitive_reachable_ids=sensitive_ids,
            blast_radius=radius,
            potential_impact=impact,
        )

    def vulnerability_context(self, vulnerability_id: str) -> VulnerabilityContext:
        snapshot = self.twin.build_snapshot()
        found = None
        owner = None
        for asset in snapshot.assets:
            for vuln in asset.vulnerabilities:
                if vuln.vulnerability_id == vulnerability_id:
                    found = vuln
                    owner = asset
                    break
            if found:
                break
        if found is None or owner is None:
            raise KeyError(vulnerability_id)

        paths = self.graph_engine.discover_paths(max_paths=40).paths
        related = [
            p
            for p in paths
            if found.identifier in p.vulnerabilities_on_path or owner.asset_id in p.asset_ids
        ]
        summaries = [" → ".join(h.asset_name for h in p.hops) for p in related[:8]]
        relevance = (
            "High — open finding on a node that appears on discovered analytical paths."
            if related and found.status == VulnerabilityStatus.OPEN
            else "Contextual — used as a synthetic condition during controlled simulation."
        )
        return VulnerabilityContext(
            vulnerability_id=found.vulnerability_id,
            identifier=found.identifier,
            name=found.name,
            asset_id=owner.asset_id,
            asset_name=owner.asset_name,
            severity=found.severity.value,
            cvss_score=found.cvss_score,
            exploitability=found.exploitability.value,
            status=found.status.value,
            remediation=None,
            is_synthetic=found.is_synthetic,
            simulation_relevance=relevance,
            related_path_count=len(related),
            related_path_summaries=summaries,
        )

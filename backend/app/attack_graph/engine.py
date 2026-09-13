"""NetworkX-based analytical attack graph engine (Review 1 foundation).

Paths are discovered from Digital Twin relationships and vulnerabilities.
This does NOT perform real exploitation.
"""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

import networkx as nx
from sqlalchemy.orm import Session

from app.core.enums import (
    AttackStage,
    Exploitability,
    EXPLOITABILITY_SCORE,
    RelationshipType,
    Severity,
    TrustLevel,
    VulnerabilityStatus,
)
from app.digital_twin import DigitalTwinService
from app.schemas.attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    AttackGraphResponse,
    AttackPath,
    AttackPathHop,
    AttackPathsResponse,
)
from app.schemas.digital_twin import DigitalTwinSnapshot, TwinAssetNode
from seed.smart_hospital_data import A

TRUST_WEIGHT = {
    TrustLevel.UNTRUSTED: 1.0,
    TrustLevel.LOW: 0.85,
    TrustLevel.MEDIUM: 0.65,
    TrustLevel.HIGH: 0.4,
    TrustLevel.FULL: 0.2,
}

SCENARIO_HINTS = [
    {
        "label": "Scenario A — IoT Compromise",
        "source": A["patient_monitor"],
        "target": A["cloud_app_server"],
    },
    {
        "label": "Scenario B — Gateway Compromise",
        "source": A["iot_gateway"],
        "target": A["patient_db"],
    },
    {
        "label": "Scenario C — User Account Compromise",
        "source": A["doctor"],
        "target": A["patient_db"],
    },
]


def _stage_for_relationship(rel_type: RelationshipType) -> AttackStage:
    if rel_type in {RelationshipType.ACCESSES, RelationshipType.AUTHENTICATES_TO}:
        return AttackStage.DATA_ACCESS
    if rel_type == RelationshipType.MANAGES:
        return AttackStage.PRIVILEGE_ESCALATION
    if rel_type in {RelationshipType.CONNECTS_TO, RelationshipType.COMMUNICATES_WITH}:
        return AttackStage.LATERAL_MOVEMENT
    return AttackStage.LATERAL_MOVEMENT


def _best_open_vuln(asset: TwinAssetNode):
    open_vulns = [v for v in asset.vulnerabilities if v.status == VulnerabilityStatus.OPEN]
    if not open_vulns:
        return None
    severity_rank = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.VERY_LOW: 1,
    }
    return max(
        open_vulns,
        key=lambda v: (severity_rank[v.severity], v.cvss_score, EXPLOITABILITY_SCORE[v.exploitability]),
    )


class AttackGraphEngine:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.twin_service = DigitalTwinService(db)

    def _build_graph(self, twin: DigitalTwinSnapshot) -> tuple[nx.DiGraph, dict[str, TwinAssetNode]]:
        graph = nx.DiGraph()
        assets = {a.asset_id: a for a in twin.assets}

        for asset in twin.assets:
            graph.add_node(
                asset.asset_id,
                asset_name=asset.asset_name,
                asset_type=asset.asset_type,
                criticality=asset.criticality,
                compromise_state="UNCOMPROMISED",
                layer=asset.layer.value,
                open_vulnerability_count=asset.open_vulnerability_count,
            )

        for edge in twin.relationships:
            source = assets.get(edge.source_asset_id)
            target = assets.get(edge.target_asset_id)
            if source is None or target is None:
                continue

            # Analytical transition uses the weaker/more exploitable endpoint vuln.
            vuln = _best_open_vuln(target) or _best_open_vuln(source)
            exploitability = vuln.exploitability if vuln else Exploitability.LOW
            trust_factor = TRUST_WEIGHT.get(edge.trust_level, 0.65)
            exploit_factor = EXPLOITABILITY_SCORE[exploitability]
            edge_risk = round(min(100.0, (0.55 * exploit_factor + 0.45 * trust_factor) * 100), 2)

            graph.add_edge(
                edge.source_asset_id,
                edge.target_asset_id,
                relationship_id=edge.relationship_id,
                relationship_type=edge.relationship_type.value,
                trust_level=edge.trust_level.value,
                vulnerability_id=vuln.vulnerability_id if vuln else None,
                vulnerability_identifier=vuln.identifier if vuln else None,
                exploitability=exploitability,
                prerequisite="network_reachability_or_trust_relationship",
                attack_stage=_stage_for_relationship(edge.relationship_type),
                edge_risk=edge_risk,
            )

        return graph, assets

    def get_graph(self) -> AttackGraphResponse:
        twin = self.twin_service.build_snapshot()
        graph, _ = self._build_graph(twin)

        nodes = [
            AttackGraphNode(
                id=node_id,
                asset_name=data["asset_name"],
                asset_type=data["asset_type"],
                criticality=data["criticality"],
                compromise_state=data["compromise_state"],
                layer=data["layer"],
                open_vulnerability_count=data["open_vulnerability_count"],
            )
            for node_id, data in graph.nodes(data=True)
        ]
        edges = [
            AttackGraphEdge(
                source=u,
                target=v,
                relationship_id=data["relationship_id"],
                relationship_type=data["relationship_type"],
                trust_level=data["trust_level"],
                vulnerability_id=data.get("vulnerability_id"),
                vulnerability_identifier=data.get("vulnerability_identifier"),
                exploitability=data.get("exploitability"),
                prerequisite=data["prerequisite"],
                attack_stage=data["attack_stage"],
                edge_risk=data["edge_risk"],
            )
            for u, v, data in graph.edges(data=True)
        ]
        return AttackGraphResponse(
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            notes=[
                "Attack graph is derived dynamically from Digital Twin relationships.",
                "Edges are analytical transitions, not real exploit chains.",
                "Edge risk is a preliminary local estimate used by path discovery.",
            ],
        )

    def discover_paths(
        self,
        *,
        source_asset_id: Optional[str] = None,
        target_asset_id: Optional[str] = None,
        max_paths: int = 25,
        max_length: int = 8,
        include_scenarios: bool = True,
    ) -> AttackPathsResponse:
        twin = self.twin_service.build_snapshot()
        graph, assets = self._build_graph(twin)
        discovered: list[AttackPath] = []

        pairs: list[tuple[str, str, Optional[str]]] = []
        if source_asset_id and target_asset_id:
            pairs.append((source_asset_id, target_asset_id, None))
        elif include_scenarios:
            for hint in SCENARIO_HINTS:
                if hint["source"] in graph and hint["target"] in graph:
                    pairs.append((hint["source"], hint["target"], hint["label"]))

        # Also discover high-value paths from IoT/user layers to critical data if no explicit pair.
        if not pairs:
            sources = [
                a.asset_id
                for a in twin.assets
                if a.layer.value in {"IOT", "USER", "EDGE"}
            ]
            targets = [
                a.asset_id
                for a in twin.assets
                if a.criticality.value >= 5 or a.asset_type.value == "DATABASE"
            ]
            for s in sources[:4]:
                for t in targets[:3]:
                    if s != t:
                        pairs.append((s, t, None))

        seen: set[tuple[str, ...]] = set()
        for source, target, label in pairs:
            if source not in graph or target not in graph:
                continue
            try:
                raw_paths = nx.all_simple_paths(graph, source, target, cutoff=max_length)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

            for node_ids in raw_paths:
                key = tuple(node_ids)
                if key in seen:
                    continue
                seen.add(key)
                discovered.append(
                    self._to_attack_path(graph, assets, list(node_ids), label)
                )
                if len(discovered) >= max_paths:
                    break
            if len(discovered) >= max_paths:
                break

        # Prefer shorter / higher edge-risk paths for presentation order
        discovered.sort(
            key=lambda p: (
                -((p.risk_score or 0)),
                p.length,
            )
        )

        return AttackPathsResponse(
            path_count=len(discovered),
            paths=discovered,
            notes=[
                "Paths computed with NetworkX all_simple_paths over relationship edges.",
                "Scenario labels are attached when a discovered path matches demo source/target pairs.",
                "No path list is hard-coded; missing topology yields empty results.",
            ],
        )

    def select_path(
        self,
        graph: nx.DiGraph,
        source: str,
        target: str,
        waypoints: Optional[list[str]] = None,
        max_length: int = 8,
    ) -> list[str]:
        """Pick a deterministic analytical path. Prefers waypoint subsequence, then shortest."""
        if source not in graph or target not in graph:
            return []
        try:
            candidates = list(nx.all_simple_paths(graph, source, target, cutoff=max_length))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        if not candidates:
            return []

        def waypoint_score(path: list[str]) -> int:
            if not waypoints:
                return 0
            idx = 0
            score = 0
            for node in path:
                if idx < len(waypoints) and node == waypoints[idx]:
                    score += 1
                    idx += 1
            return score

        candidates.sort(key=lambda p: (-waypoint_score(p), len(p), tuple(p)))
        return list(candidates[0])

    def _to_attack_path(
        self,
        graph: nx.DiGraph,
        assets: dict[str, TwinAssetNode],
        node_ids: list[str],
        scenario_label: Optional[str],
    ) -> AttackPath:
        hops = [
            AttackPathHop(
                asset_id=nid,
                asset_name=assets[nid].asset_name,
                asset_type=assets[nid].asset_type,
            )
            for nid in node_ids
        ]
        vuln_ids: list[str] = []
        edge_risks: list[float] = []
        for u, v in zip(node_ids, node_ids[1:]):
            data = graph.edges[u, v]
            edge_risks.append(float(data.get("edge_risk", 0)))
            ident = data.get("vulnerability_identifier")
            if ident:
                vuln_ids.append(ident)

        # Preliminary path risk (final scored by risk engine when available)
        avg_edge = sum(edge_risks) / len(edge_risks) if edge_risks else 0.0
        length_penalty = max(0.0, 1.0 - (len(node_ids) - 2) * 0.05)
        prelim = round(min(100.0, avg_edge * (0.7 + 0.3 * length_penalty)), 2)

        names = " → ".join(h.asset_name for h in hops)
        explanation = (
            f"Analytical path {names}. "
            f"Derived from {len(node_ids) - 1} relationship edge(s) in the Digital Twin. "
            f"Associated synthetic findings on transitions: {', '.join(vuln_ids) if vuln_ids else 'none'}."
        )
        if scenario_label:
            explanation = f"{scenario_label}. {explanation}"

        return AttackPath(
            path_id=str(uuid4()),
            source_asset_id=node_ids[0],
            source_name=assets[node_ids[0]].asset_name,
            target_asset_id=node_ids[-1],
            target_name=assets[node_ids[-1]].asset_name,
            hops=hops,
            asset_ids=node_ids,
            stage_count=max(0, len(node_ids) - 1),
            length=len(node_ids),
            vulnerabilities_on_path=sorted(set(vuln_ids)),
            scenario_label=scenario_label,
            explanation=explanation,
            risk_score=prelim,
            risk_band=None,
        )

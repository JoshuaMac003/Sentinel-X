"""Controlled, deterministic Digital Twin attack simulation (Review 2).

Operates only on synthetic graph state. No real exploitation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.attack_graph import AttackGraphEngine
from app.core.config import get_settings
from app.core.enums import (
    AttackType,
    Criticality,
    EXPLOITABILITY_SCORE,
    Exploitability,
    SimulationAction,
    SimulationResult,
    SimulationState,
    TrustLevel,
    VulnerabilityStatus,
    risk_band_from_score,
)
from app.digital_twin import DigitalTwinService
from app.models import (
    Asset,
    AttackScenario,
    SimulationEvent,
    SimulationImpact,
    SimulationRun,
)
from app.risk import BaselineRiskEngine
from app.schemas.digital_twin import TwinAssetNode
from app.schemas.risk import RiskFactor
from app.schemas.simulation import (
    RiskComparisonRead,
    ScenarioRead,
    SimulationCreate,
    SimulationEventRead,
    SimulationImpactRead,
    SimulationRead,
    SimulationSummary,
)
from app.simulation.mapping import SecurityMappingService, _best_open_identifier, _is_sensitive, _is_vulnerable
from app.simulation.rules import evaluate_hop, evaluate_initial_access


class SimulationEngine:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.twin = DigitalTwinService(db)
        self.graph_engine = AttackGraphEngine(db)
        self.risk = BaselineRiskEngine(db)
        self.mapping = SecurityMappingService(db)
        self.settings = get_settings()

    def list_scenarios(self) -> list[ScenarioRead]:
        rows = self.db.scalars(
            select(AttackScenario).order_by(AttackScenario.scenario_code.asc())
        ).all()
        assets = {a.asset_id: a for a in self.db.scalars(select(Asset)).all()}
        return [self._to_scenario(row, assets) for row in rows]

    def get_scenario(self, scenario_id: str) -> ScenarioRead:
        row = self.db.get(AttackScenario, scenario_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
        assets = {a.asset_id: a for a in self.db.scalars(select(Asset)).all()}
        return self._to_scenario(row, assets)

    def run(self, payload: SimulationCreate) -> SimulationRead:
        snapshot = self.twin.build_snapshot()
        assets = {a.asset_id: a for a in snapshot.assets}
        scenario: Optional[AttackScenario] = None
        waypoints: list[str] = []

        if payload.scenario_id:
            scenario = self.db.get(AttackScenario, payload.scenario_id)
            if scenario is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "Scenario not found")
            if not scenario.enabled:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Scenario is disabled")
            source_id = scenario.source_asset_id
            target_id = scenario.target_asset_id
            if scenario.preferred_waypoints_json:
                waypoints = json.loads(scenario.preferred_waypoints_json)
        else:
            if not payload.source_asset_id or not payload.target_asset_id:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Provide scenario_id or both source_asset_id and target_asset_id",
                )
            source_id = payload.source_asset_id
            target_id = payload.target_asset_id

        if source_id not in assets or target_id not in assets:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid source or target asset")

        events: list[SimulationEvent] = []
        step = 1
        events.append(
            self._event(
                step,
                None,
                source_id,
                SimulationAction.VALIDATE,
                "Scenario and assets validated against the current Digital Twin.",
                True,
                SimulationState.NORMAL,
                SimulationState.NORMAL,
            )
        )
        step += 1

        graph, _ = self.graph_engine._build_graph(snapshot)
        chosen = self.graph_engine.select_path(graph, source_id, target_id, waypoints)

        if not chosen:
            events.append(
                self._event(
                    step,
                    source_id,
                    target_id,
                    SimulationAction.BLOCK,
                    "No analytical path exists between source and target in the Digital Twin graph.",
                    False,
                    SimulationState.NORMAL,
                    SimulationState.NORMAL,
                )
            )
            return self._persist(
                scenario,
                SimulationResult.NO_PATH,
                False,
                "No analytical path exists between source and target.",
                [],
                [],
                events,
                assets,
                source_id,
            )

        compromised: list[str] = []
        ok, reason, vuln_id = evaluate_initial_access(assets[source_id])
        prev = SimulationState.NORMAL
        new = SimulationState.COMPROMISED if ok else SimulationState.NORMAL
        events.append(
            self._event(
                step,
                None,
                source_id,
                SimulationAction.INITIAL_ACCESS,
                reason,
                ok,
                prev,
                new,
                vuln_id,
                8.0 if ok else 0.0,
            )
        )
        step += 1
        if not ok:
            return self._persist(
                scenario,
                SimulationResult.BLOCKED,
                False,
                reason,
                chosen,
                [],
                events,
                assets,
                source_id,
            )

        compromised.append(source_id)
        blocked_reason: Optional[str] = None

        for src, dst in zip(chosen, chosen[1:]):
            src_asset = assets[src]
            dst_asset = assets[dst]
            edge_data = graph.edges[src, dst]
            hop_ok, hop_reason, hop_vuln = evaluate_hop(
                src_asset,
                dst_asset,
                edge_data,
                min_exploitability=self._min_exploitability(),
            )
            events.append(
                self._event(
                    step,
                    src,
                    dst,
                    SimulationAction.PROPAGATE if hop_ok else SimulationAction.BLOCK,
                    hop_reason,
                    hop_ok,
                    SimulationState.COMPROMISED,
                    SimulationState.COMPROMISED if hop_ok else SimulationState.NORMAL,
                    hop_vuln,
                    6.0 if hop_ok else 0.0,
                )
            )
            step += 1
            if not hop_ok:
                blocked_reason = hop_reason
                break
            if dst not in compromised:
                compromised.append(dst)

        target_reached = target_id in compromised and blocked_reason is None
        if target_reached:
            events.append(
                self._event(
                    step,
                    chosen[-2] if len(chosen) > 1 else source_id,
                    target_id,
                    SimulationAction.TARGET_REACHED,
                    f"Analytical simulation reached target {assets[target_id].asset_name}.",
                    True,
                    SimulationState.COMPROMISED,
                    SimulationState.COMPROMISED,
                    _best_open_identifier(assets[target_id]),
                    12.0,
                )
            )
            result = SimulationResult.SUCCESS
            block = None
        else:
            result = SimulationResult.BLOCKED
            block = blocked_reason or "Propagation stopped before the target."

        return self._persist(
            scenario,
            result,
            target_reached,
            block,
            chosen,
            compromised,
            events,
            assets,
            source_id,
        )

    def get(self, simulation_id: str) -> SimulationRead:
        run = self.db.scalars(
            select(SimulationRun)
            .where(SimulationRun.simulation_id == simulation_id)
            .options(
                selectinload(SimulationRun.events),
                selectinload(SimulationRun.impact),
                selectinload(SimulationRun.scenario),
            )
        ).first()
        if run is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Simulation not found")
        return self._to_read(run)

    def list_runs(self) -> list[SimulationSummary]:
        rows = self.db.scalars(
            select(SimulationRun)
            .options(selectinload(SimulationRun.scenario), selectinload(SimulationRun.impact))
            .order_by(SimulationRun.created_at.desc())
        ).all()
        out: list[SimulationSummary] = []
        for run in rows:
            compromised = json.loads(run.compromised_assets_json or "[]")
            events = self.db.scalars(
                select(SimulationEvent).where(SimulationEvent.simulation_id == run.simulation_id)
            ).all()
            out.append(
                SimulationSummary(
                    simulation_id=run.simulation_id,
                    scenario_id=run.scenario_id,
                    scenario_code=run.scenario.scenario_code if run.scenario else None,
                    scenario_name=run.scenario.scenario_name if run.scenario else None,
                    result=run.result,
                    target_reached=run.target_reached,
                    step_count=len(events),
                    compromised_count=len(compromised),
                    impact_score=run.impact.impact_score if run.impact else None,
                    baseline_risk=run.baseline_risk,
                    simulation_risk=run.simulation_risk,
                    risk_change=run.risk_change,
                    created_at=run.created_at,
                    block_reason=run.block_reason,
                )
            )
        return out

    def comparison(self, simulation_id: str) -> RiskComparisonRead:
        read = self.get(simulation_id)
        if read.risk_comparison is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Risk comparison unavailable")
        return read.risk_comparison

    def _min_exploitability(self) -> Exploitability:
        raw = (self.settings.sim_min_exploitability or "LOW").upper()
        try:
            return Exploitability(raw)
        except ValueError:
            return Exploitability.LOW

    def _event(
        self,
        step: int,
        source: Optional[str],
        target: Optional[str],
        action: SimulationAction,
        reason: str,
        success: bool,
        previous: SimulationState,
        new: SimulationState,
        vuln: Optional[str] = None,
        risk_impact: float = 0.0,
    ) -> SimulationEvent:
        return SimulationEvent(
            event_id=str(uuid4()),
            step_number=step,
            source_asset_id=source,
            target_asset_id=target,
            action=action,
            reason=reason,
            vulnerability_identifier=vuln,
            previous_state=previous,
            new_state=new,
            success=success,
            risk_impact=risk_impact,
        )

    def _persist(
        self,
        scenario: Optional[AttackScenario],
        result: SimulationResult,
        target_reached: bool,
        block_reason: Optional[str],
        path: list[str],
        compromised: list[str],
        events: list[SimulationEvent],
        assets: dict[str, TwinAssetNode],
        origin_id: str,
    ) -> SimulationRead:
        overview = self.risk.overview()
        baseline = overview.overall_risk_score
        radius = self.mapping.blast_radius(origin_id)

        total_assets = max(1, len(assets))
        critical_total = max(
            1, sum(1 for a in assets.values() if a.criticality == Criticality.CRITICAL)
        )
        sensitive_total = max(1, sum(1 for a in assets.values() if _is_sensitive(a)))
        compromised_set = set(compromised)
        critical_reached = sum(
            1 for aid in compromised_set if assets[aid].criticality == Criticality.CRITICAL
        )
        sensitive_reached = sum(1 for aid in compromised_set if _is_sensitive(assets[aid]))
        depth = max(0, len(compromised) - 1) if compromised else 0
        vulnerable_reachable = radius.vulnerable_reachable_count

        factors = [
            RiskFactor(
                name="compromised_share",
                value=round(len(compromised) / total_assets, 4),
                weight=0.30,
                weighted_contribution=round(0.30 * len(compromised) / total_assets, 4),
                contribution=round(30.0 * len(compromised) / total_assets, 2),
                detail=f"{len(compromised)} of {total_assets} assets compromised in this run",
            ),
            RiskFactor(
                name="critical_exposure",
                value=round(critical_reached / critical_total, 4),
                weight=0.25,
                weighted_contribution=round(0.25 * critical_reached / critical_total, 4),
                contribution=round(25.0 * critical_reached / critical_total, 2),
                detail=f"{critical_reached} critical asset(s) reached",
            ),
            RiskFactor(
                name="sensitive_data_exposure",
                value=round(sensitive_reached / sensitive_total, 4),
                weight=0.20,
                weighted_contribution=round(0.20 * sensitive_reached / sensitive_total, 4),
                contribution=round(20.0 * sensitive_reached / sensitive_total, 2),
                detail=f"{sensitive_reached} sensitive-data asset(s) reached",
            ),
            RiskFactor(
                name="propagation_depth",
                value=round(min(1.0, depth / 6.0), 4),
                weight=0.15,
                weighted_contribution=round(0.15 * min(1.0, depth / 6.0), 4),
                contribution=round(15.0 * min(1.0, depth / 6.0), 2),
                detail=f"propagation_depth={depth}",
            ),
            RiskFactor(
                name="blast_radius",
                value=round(radius.impact_score / 100.0, 4),
                weight=0.10,
                weighted_contribution=round(0.10 * radius.impact_score / 100.0, 4),
                contribution=round(0.10 * radius.impact_score, 2),
                detail=radius.explanation,
            ),
        ]
        impact_score = round(min(100.0, sum(f.contribution for f in factors)), 2)
        b_w = self.settings.sim_risk_weight_baseline
        i_w = self.settings.sim_risk_weight_impact
        total_w = (b_w + i_w) or 1.0
        b_w, i_w = b_w / total_w, i_w / total_w
        sim_risk = round(min(100.0, b_w * baseline + i_w * impact_score), 2)
        change = round(sim_risk - baseline, 2)

        run = SimulationRun(
            simulation_id=str(uuid4()),
            scenario_id=scenario.scenario_id if scenario else None,
            result=result,
            target_reached=target_reached,
            block_reason=block_reason,
            path_json=json.dumps(path),
            compromised_assets_json=json.dumps(compromised),
            isolated_assets_json=json.dumps([]),
            baseline_risk=baseline,
            simulation_risk=sim_risk,
            risk_change=change,
            explanation=(
                f"Result={result.value}. Baseline={baseline}, impact={impact_score}, "
                f"simulation_risk={sim_risk} (change {change:+}). Rule-based only — not ML."
            ),
            model_version="simulation-v1",
        )
        self.db.add(run)
        self.db.flush()
        for ev in events:
            ev.simulation_id = run.simulation_id
            self.db.add(ev)

        impact = SimulationImpact(
            impact_id=str(uuid4()),
            simulation_id=run.simulation_id,
            propagation_depth=depth,
            compromised_count=len(compromised),
            reachable_count=radius.reachable_asset_count,
            vulnerable_reachable_count=vulnerable_reachable,
            critical_reached_count=critical_reached,
            sensitive_data_reached_count=sensitive_reached,
            target_reached=target_reached,
            maximum_propagation_depth=radius.maximum_propagation_depth,
            impact_score=impact_score,
            blast_radius_score=radius.impact_score,
            factors_json=json.dumps([f.model_dump() for f in factors]),
            explanation=(
                f"Analytical impact score {impact_score}/100 from compromised share, critical "
                f"exposure, sensitive-data exposure, depth, and blast radius."
            ),
        )
        self.db.add(impact)
        self.db.commit()
        return self.get(run.simulation_id)

    def _to_scenario(self, row: AttackScenario, assets: dict[str, Asset]) -> ScenarioRead:
        waypoints = json.loads(row.preferred_waypoints_json) if row.preferred_waypoints_json else []
        src = assets.get(row.source_asset_id)
        dst = assets.get(row.target_asset_id)
        return ScenarioRead(
            scenario_id=row.scenario_id,
            scenario_code=row.scenario_code,
            scenario_name=row.scenario_name,
            description=row.description,
            source_asset_id=row.source_asset_id,
            source_name=src.asset_name if src else row.source_asset_id,
            target_asset_id=row.target_asset_id,
            target_name=dst.asset_name if dst else row.target_asset_id,
            attack_type=row.attack_type,
            enabled=row.enabled,
            preferred_waypoints=waypoints,
            notes=row.notes,
        )

    def _to_read(self, run: SimulationRun) -> SimulationRead:
        assets = {a.asset_id: a for a in self.db.scalars(select(Asset)).all()}
        names = {i: a.asset_name for i, a in assets.items()}
        path = json.loads(run.path_json or "[]")
        compromised = json.loads(run.compromised_assets_json or "[]")
        isolated = json.loads(run.isolated_assets_json or "[]")
        scenario = None
        if run.scenario:
            scenario = self._to_scenario(run.scenario, assets)

        events = []
        for ev in sorted(run.events, key=lambda e: e.step_number):
            events.append(
                SimulationEventRead(
                    event_id=ev.event_id,
                    simulation_id=run.simulation_id,
                    step_number=ev.step_number,
                    source_asset_id=ev.source_asset_id,
                    source_name=names.get(ev.source_asset_id) if ev.source_asset_id else None,
                    target_asset_id=ev.target_asset_id,
                    target_name=names.get(ev.target_asset_id) if ev.target_asset_id else None,
                    action=ev.action,
                    reason=ev.reason,
                    vulnerability_identifier=ev.vulnerability_identifier,
                    previous_state=ev.previous_state,
                    new_state=ev.new_state,
                    success=ev.success,
                    risk_impact=ev.risk_impact,
                    timestamp=ev.created_at,
                )
            )

        impact_read = None
        if run.impact:
            factors = []
            if run.impact.factors_json:
                factors = [RiskFactor(**f) for f in json.loads(run.impact.factors_json)]
            radius = self.mapping.blast_radius(path[0] if path else compromised[0]) if (path or compromised) else None
            impact_read = SimulationImpactRead(
                impact_id=run.impact.impact_id,
                simulation_id=run.simulation_id,
                propagation_depth=run.impact.propagation_depth,
                compromised_count=run.impact.compromised_count,
                reachable_count=run.impact.reachable_count,
                vulnerable_reachable_count=run.impact.vulnerable_reachable_count,
                critical_reached_count=run.impact.critical_reached_count,
                sensitive_data_reached_count=run.impact.sensitive_data_reached_count,
                target_reached=run.impact.target_reached,
                maximum_propagation_depth=run.impact.maximum_propagation_depth,
                impact_score=run.impact.impact_score,
                blast_radius_score=run.impact.blast_radius_score,
                blast_radius=radius,
                factors=factors,
                explanation=run.impact.explanation,
                propagation_path=path,
                compromised_asset_ids=compromised,
                compromised_asset_names=[names.get(i, i) for i in compromised],
            )

        comparison = None
        if run.baseline_risk is not None and run.simulation_risk is not None:
            comparison = RiskComparisonRead(
                simulation_id=run.simulation_id,
                baseline_risk=run.baseline_risk,
                baseline_band=risk_band_from_score(run.baseline_risk),
                simulation_risk=run.simulation_risk,
                simulation_band=risk_band_from_score(run.simulation_risk),
                risk_change=run.risk_change or 0.0,
                factors=impact_read.factors if impact_read else [],
                explanation=(
                    f"Baseline {run.baseline_risk} → simulation {run.simulation_risk} "
                    f"(Δ {run.risk_change:+}). Blend of baseline-v1 and simulation impact. Not ML."
                ),
                notes=[
                    "Baseline engine is unchanged from Review 1.",
                    "Simulation risk is an analytical overlay for this run only.",
                ],
            )

        return SimulationRead(
            simulation_id=run.simulation_id,
            scenario=scenario,
            result=run.result,
            target_reached=run.target_reached,
            block_reason=run.block_reason,
            path_asset_ids=path,
            path_display=" → ".join(names.get(i, i) for i in path),
            compromised_asset_ids=compromised,
            isolated_asset_ids=isolated,
            events=events,
            impact=impact_read,
            risk_comparison=comparison,
            explanation=run.explanation,
            model_version=run.model_version,
            created_at=run.created_at,
        )

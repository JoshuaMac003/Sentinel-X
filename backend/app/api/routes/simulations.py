"""API routes for attack scenarios, controlled simulation runs, events, and impact analysis (Review 2)."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.simulation import (
    RiskComparisonRead,
    ScenarioRead,
    SimulationCreate,
    SimulationEventRead,
    SimulationImpactRead,
    SimulationRead,
    SimulationSummary,
)
from app.simulation import SimulationEngine

router = APIRouter(prefix="", tags=["Attack Simulation"])


@router.get("/scenarios", response_model=list[ScenarioRead])
def list_scenarios(db: Session = Depends(get_db)) -> list[ScenarioRead]:
    """List formal synthetic attack scenarios (Scenario A, B, C, D)."""
    return SimulationEngine(db).list_scenarios()


@router.get("/scenarios/{scenario_id}", response_model=ScenarioRead)
def get_scenario(scenario_id: str, db: Session = Depends(get_db)) -> ScenarioRead:
    """Get details for a specific formal attack scenario."""
    return SimulationEngine(db).get_scenario(scenario_id)


@router.post("/simulations", response_model=SimulationRead, status_code=status.HTTP_201_CREATED)
def run_simulation(
    payload: SimulationCreate, db: Session = Depends(get_db)
) -> SimulationRead:
    """Execute a controlled, deterministic Digital Twin attack simulation."""
    return SimulationEngine(db).run(payload)


@router.get("/simulations", response_model=list[SimulationSummary])
def list_simulations(db: Session = Depends(get_db)) -> list[SimulationSummary]:
    """List history of controlled simulation runs."""
    return SimulationEngine(db).list_runs()


@router.get("/simulations/{simulation_id}", response_model=SimulationRead)
def get_simulation(simulation_id: str, db: Session = Depends(get_db)) -> SimulationRead:
    """Get full details and results of a specific simulation run."""
    return SimulationEngine(db).get(simulation_id)


@router.get("/simulations/{simulation_id}/events", response_model=list[SimulationEventRead])
def get_simulation_events(
    simulation_id: str, db: Session = Depends(get_db)
) -> list[SimulationEventRead]:
    """Get step-by-step event timeline for a simulation run."""
    sim = SimulationEngine(db).get(simulation_id)
    return sim.events


@router.get("/simulations/{simulation_id}/impact", response_model=SimulationImpactRead)
def get_simulation_impact(
    simulation_id: str, db: Session = Depends(get_db)
) -> SimulationImpactRead:
    """Get blast radius and impact metrics for a simulation run."""
    sim = SimulationEngine(db).get(simulation_id)
    if sim.impact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Impact metrics not available for this simulation run.",
        )
    return sim.impact


@router.get("/simulations/{simulation_id}/risk-comparison", response_model=RiskComparisonRead)
def get_simulation_risk_comparison(
    simulation_id: str, db: Session = Depends(get_db)
) -> RiskComparisonRead:
    """Get baseline vs simulation-impact risk comparison for a simulation run."""
    return SimulationEngine(db).comparison(simulation_id)

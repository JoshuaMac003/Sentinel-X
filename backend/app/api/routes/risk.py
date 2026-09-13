from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.risk import BaselineRiskEngine
from app.schemas.risk import AssetRisk, PathRisk, RiskOverview
from app.schemas.simulation import RiskComparisonRead
from app.simulation import SimulationEngine

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.get("", response_model=RiskOverview)
@router.get("/overview", response_model=RiskOverview)
def risk_overview(db: Session = Depends(get_db)) -> RiskOverview:
    """Baseline risk overview (also available as GET /api/risk)."""
    return BaselineRiskEngine(db).overview()


@router.get("/assets", response_model=list[AssetRisk])
def risk_assets(db: Session = Depends(get_db)) -> list[AssetRisk]:
    return BaselineRiskEngine(db).assess_assets()


@router.get("/paths", response_model=list[PathRisk])
def risk_paths(db: Session = Depends(get_db)) -> list[PathRisk]:
    return BaselineRiskEngine(db).assess_paths()


@router.get("/comparison", response_model=RiskComparisonRead)
def risk_comparison(
    simulation_id: Optional[str] = Query(None, description="Simulation ID (defaults to latest run)"),
    db: Session = Depends(get_db),
) -> RiskComparisonRead:
    """Compare baseline risk against simulation impact risk for a run."""
    engine = SimulationEngine(db)
    target_id = simulation_id
    if not target_id:
        runs = engine.list_runs()
        if not runs:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No simulation runs exist yet. Execute a simulation to see risk comparison.",
            )
        target_id = runs[0].simulation_id
    return engine.comparison(target_id)

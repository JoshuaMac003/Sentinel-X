"""Attack Graph API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.attack_graph import AttackGraphEngine
from app.database import get_db
from app.risk import BaselineRiskEngine
from app.schemas.attack_graph import AttackGraphResponse, AttackPathsResponse

router = APIRouter(tags=["Attack Graph"])


@router.get("/attack-graph", response_model=AttackGraphResponse)
def get_attack_graph(db: Session = Depends(get_db)) -> AttackGraphResponse:
    return AttackGraphEngine(db).get_graph()


@router.get("/attack-paths", response_model=AttackPathsResponse)
def get_attack_paths(
    source_asset_id: Optional[str] = Query(default=None),
    target_asset_id: Optional[str] = Query(default=None),
    max_paths: int = Query(default=25, ge=1, le=100),
    max_length: int = Query(default=8, ge=2, le=12),
    db: Session = Depends(get_db),
) -> AttackPathsResponse:
    engine = AttackGraphEngine(db)
    response = engine.discover_paths(
        source_asset_id=source_asset_id,
        target_asset_id=target_asset_id,
        max_paths=max_paths,
        max_length=max_length,
        include_scenarios=source_asset_id is None and target_asset_id is None,
    )
    risk_engine = BaselineRiskEngine(db)
    asset_scores = {a.asset_id: a for a in risk_engine.assess_assets()}
    for path in response.paths:
        scored = risk_engine.score_path(path, asset_scores)
        path.risk_score = scored.risk_score
        path.risk_band = scored.risk_band
        path.explanation = scored.explanation
    return response

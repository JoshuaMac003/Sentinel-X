"""Digital Twin API routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.digital_twin import DigitalTwinService
from app.schemas.digital_twin import DigitalTwinSnapshot, TwinTopology

router = APIRouter(prefix="/digital-twin", tags=["Digital Twin"])


@router.get("", response_model=DigitalTwinSnapshot)
def get_digital_twin(db: Session = Depends(get_db)) -> DigitalTwinSnapshot:
    return DigitalTwinService(db).build_snapshot()


@router.get("/topology", response_model=TwinTopology)
def get_digital_twin_topology(db: Session = Depends(get_db)) -> TwinTopology:
    return DigitalTwinService(db).build_topology()

"""Vulnerability API routes."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.vulnerabilities import (
    VulnerabilityCreate,
    VulnerabilityRead,
    VulnerabilityUpdate,
)
from app.services.vulnerabilities import VulnerabilityService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    asset_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[VulnerabilityRead]:
    return VulnerabilityService(db).list_vulnerabilities(asset_id=asset_id)


@router.get("/{vulnerability_id}", response_model=VulnerabilityRead)
def get_vulnerability(
    vulnerability_id: str, db: Session = Depends(get_db)
) -> VulnerabilityRead:
    return VulnerabilityService(db).get_vulnerability(vulnerability_id)


@router.post("", response_model=VulnerabilityRead, status_code=status.HTTP_201_CREATED)
def create_vulnerability(
    payload: VulnerabilityCreate, db: Session = Depends(get_db)
) -> VulnerabilityRead:
    return VulnerabilityService(db).create_vulnerability(payload)


@router.put("/{vulnerability_id}", response_model=VulnerabilityRead)
def update_vulnerability(
    vulnerability_id: str,
    payload: VulnerabilityUpdate,
    db: Session = Depends(get_db),
) -> VulnerabilityRead:
    return VulnerabilityService(db).update_vulnerability(vulnerability_id, payload)

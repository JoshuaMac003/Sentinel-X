"""Vulnerability service."""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Vulnerability
from app.schemas.vulnerabilities import VulnerabilityCreate, VulnerabilityUpdate


class VulnerabilityService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_vulnerabilities(self, asset_id: str | None = None) -> list[Vulnerability]:
        stmt = select(Vulnerability).order_by(Vulnerability.cvss_score.desc())
        if asset_id:
            stmt = stmt.where(Vulnerability.asset_id == asset_id)
        return list(self.db.scalars(stmt).all())

    def get_vulnerability(self, vulnerability_id: str) -> Vulnerability:
        vuln = self.db.get(Vulnerability, vulnerability_id)
        if vuln is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found"
            )
        return vuln

    def create_vulnerability(self, payload: VulnerabilityCreate) -> Vulnerability:
        if self.db.get(Asset, payload.asset_id) is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="asset_id must reference an existing asset",
            )
        if payload.identifier.upper().startswith("CVE-") and payload.is_synthetic:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Do not invent CVE identifiers. Use SYN-* labels for synthetic vulns.",
            )

        vuln = Vulnerability(**payload.model_dump())
        self.db.add(vuln)
        self.db.commit()
        self.db.refresh(vuln)
        return vuln

    def update_vulnerability(
        self, vulnerability_id: str, payload: VulnerabilityUpdate
    ) -> Vulnerability:
        vuln = self.get_vulnerability(vulnerability_id)
        updates = payload.model_dump(exclude_unset=True)
        for key, value in updates.items():
            setattr(vuln, key, value)
        self.db.commit()
        self.db.refresh(vuln)
        return vuln

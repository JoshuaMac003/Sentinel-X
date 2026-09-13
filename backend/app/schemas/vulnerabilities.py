"""Pydantic schemas for vulnerabilities."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import Exploitability, Severity, VulnerabilityStatus


class VulnerabilityBase(BaseModel):
    asset_id: str
    identifier: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = None
    severity: Severity
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    exploitability: Exploitability
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    remediation: Optional[str] = None
    is_synthetic: bool = True


class VulnerabilityCreate(VulnerabilityBase):
    pass


class VulnerabilityUpdate(BaseModel):
    identifier: Optional[str] = Field(default=None, min_length=1, max_length=64)
    name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    description: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    exploitability: Optional[Exploitability] = None
    status: Optional[VulnerabilityStatus] = None
    remediation: Optional[str] = None
    is_synthetic: Optional[bool] = None


class VulnerabilityRead(VulnerabilityBase):
    model_config = ConfigDict(from_attributes=True)

    vulnerability_id: str
    created_at: datetime
    updated_at: datetime

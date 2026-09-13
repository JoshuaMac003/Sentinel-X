"""Pydantic schemas for assets and related entities."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AssetLayer, AssetStatus, AssetType, Criticality, TrustLevel


class AssetServiceBase(BaseModel):
    service_name: str = Field(..., min_length=1, max_length=128)
    protocol: Optional[str] = Field(default=None, max_length=32)
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    description: Optional[str] = None


class AssetServiceCreate(AssetServiceBase):
    pass


class AssetServiceRead(AssetServiceBase):
    model_config = ConfigDict(from_attributes=True)

    service_id: str
    asset_id: str
    created_at: datetime
    updated_at: datetime


class AssetBase(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=128)
    asset_type: AssetType
    layer: AssetLayer
    description: Optional[str] = None
    ip_address: Optional[str] = Field(default=None, max_length=64)
    operating_system: Optional[str] = Field(default=None, max_length=128)
    criticality: Criticality = Criticality.MEDIUM
    trust_level: TrustLevel = TrustLevel.MEDIUM
    status: AssetStatus = AssetStatus.ACTIVE
    metadata_json: Optional[str] = None


class AssetCreate(AssetBase):
    services: list[AssetServiceCreate] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    asset_name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    asset_type: Optional[AssetType] = None
    layer: Optional[AssetLayer] = None
    description: Optional[str] = None
    ip_address: Optional[str] = Field(default=None, max_length=64)
    operating_system: Optional[str] = Field(default=None, max_length=128)
    criticality: Optional[Criticality] = None
    trust_level: Optional[TrustLevel] = None
    status: Optional[AssetStatus] = None
    metadata_json: Optional[str] = None
    services: Optional[list[AssetServiceCreate]] = None


class AssetRead(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    services: list[AssetServiceRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AssetSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    asset_name: str
    asset_type: AssetType
    layer: AssetLayer
    criticality: Criticality
    status: AssetStatus

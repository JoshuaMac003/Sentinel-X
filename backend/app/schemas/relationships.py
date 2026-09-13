"""Pydantic schemas for asset relationships."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.enums import RelationshipType, TrustLevel


class RelationshipBase(BaseModel):
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    protocol: Optional[str] = Field(default=None, max_length=32)
    port: Optional[int] = Field(default=None, ge=0, le=65535)
    trust_level: TrustLevel = TrustLevel.MEDIUM
    description: Optional[str] = None

    @model_validator(mode="after")
    def reject_self_loop(self) -> "RelationshipBase":
        if self.source_asset_id == self.target_asset_id:
            raise ValueError("source_asset_id and target_asset_id must differ")
        return self


class RelationshipCreate(RelationshipBase):
    pass


class RelationshipRead(RelationshipBase):
    model_config = ConfigDict(from_attributes=True)

    relationship_id: str
    created_at: datetime
    updated_at: datetime

"""Relationship service."""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, AssetRelationship
from app.schemas.relationships import RelationshipCreate


class RelationshipService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_relationships(self) -> list[AssetRelationship]:
        stmt = select(AssetRelationship).order_by(AssetRelationship.created_at.asc())
        return list(self.db.scalars(stmt).all())

    def create_relationship(self, payload: RelationshipCreate) -> AssetRelationship:
        source = self.db.get(Asset, payload.source_asset_id)
        target = self.db.get(Asset, payload.target_asset_id)
        if source is None or target is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="source_asset_id and target_asset_id must reference existing assets",
            )

        existing = self.db.scalars(
            select(AssetRelationship).where(
                AssetRelationship.source_asset_id == payload.source_asset_id,
                AssetRelationship.target_asset_id == payload.target_asset_id,
                AssetRelationship.relationship_type == payload.relationship_type,
                AssetRelationship.protocol == payload.protocol,
                AssetRelationship.port == payload.port,
            )
        ).first()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Equivalent relationship already exists",
            )

        rel = AssetRelationship(**payload.model_dump())
        self.db.add(rel)
        self.db.commit()
        self.db.refresh(rel)
        return rel

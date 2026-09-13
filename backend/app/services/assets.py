"""Asset service — CRUD and service association."""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import Asset, AssetService
from app.schemas.assets import AssetCreate, AssetUpdate


class AssetServiceLayer:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_assets(self) -> list[Asset]:
        stmt = (
            select(Asset)
            .options(selectinload(Asset.services))
            .order_by(Asset.asset_name.asc())
        )
        return list(self.db.scalars(stmt).all())

    def get_asset(self, asset_id: str) -> Asset:
        asset = self.db.scalars(
            select(Asset)
            .where(Asset.asset_id == asset_id)
            .options(selectinload(Asset.services))
        ).first()
        if asset is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        return asset

    def create_asset(self, payload: AssetCreate) -> Asset:
        existing = self.db.scalars(
            select(Asset).where(Asset.asset_name == payload.asset_name)
        ).first()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Asset name '{payload.asset_name}' already exists",
            )

        data = payload.model_dump(exclude={"services"})
        asset = Asset(**data)
        for service in payload.services:
            asset.services.append(AssetService(**service.model_dump()))

        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return self.get_asset(asset.asset_id)

    def update_asset(self, asset_id: str, payload: AssetUpdate) -> Asset:
        asset = self.get_asset(asset_id)
        updates = payload.model_dump(exclude_unset=True, exclude={"services"})

        if "asset_name" in updates and updates["asset_name"] != asset.asset_name:
            conflict = self.db.scalars(
                select(Asset).where(Asset.asset_name == updates["asset_name"])
            ).first()
            if conflict is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Asset name '{updates['asset_name']}' already exists",
                )

        for key, value in updates.items():
            setattr(asset, key, value)

        if payload.services is not None:
            asset.services.clear()
            for service in payload.services:
                asset.services.append(AssetService(**service.model_dump()))

        self.db.commit()
        return self.get_asset(asset_id)

    def delete_asset(self, asset_id: str) -> None:
        asset = self.get_asset(asset_id)
        self.db.delete(asset)
        self.db.commit()

"""Asset API routes."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.assets import AssetCreate, AssetRead, AssetUpdate
from app.schemas.common import MessageResponse
from app.services.assets import AssetServiceLayer

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=list[AssetRead])
def list_assets(db: Session = Depends(get_db)) -> list[AssetRead]:
    return AssetServiceLayer(db).list_assets()


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: str, db: Session = Depends(get_db)) -> AssetRead:
    return AssetServiceLayer(db).get_asset(asset_id)


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)) -> AssetRead:
    return AssetServiceLayer(db).create_asset(payload)


@router.put("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: str, payload: AssetUpdate, db: Session = Depends(get_db)
) -> AssetRead:
    return AssetServiceLayer(db).update_asset(asset_id, payload)


@router.delete("/{asset_id}", response_model=MessageResponse)
def delete_asset(asset_id: str, db: Session = Depends(get_db)) -> MessageResponse:
    AssetServiceLayer(db).delete_asset(asset_id)
    return MessageResponse(message=f"Asset {asset_id} deleted")

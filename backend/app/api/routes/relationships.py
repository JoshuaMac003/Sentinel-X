"""Relationship API routes."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.relationships import RelationshipCreate, RelationshipRead
from app.services.relationships import RelationshipService

router = APIRouter(prefix="/relationships", tags=["Relationships"])


@router.get("", response_model=list[RelationshipRead])
def list_relationships(db: Session = Depends(get_db)) -> list[RelationshipRead]:
    return RelationshipService(db).list_relationships()


@router.post("", response_model=RelationshipRead, status_code=status.HTTP_201_CREATED)
def create_relationship(
    payload: RelationshipCreate, db: Session = Depends(get_db)
) -> RelationshipRead:
    return RelationshipService(db).create_relationship(payload)

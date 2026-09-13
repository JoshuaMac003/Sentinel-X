"""Admin / utility routes."""

from fastapi import APIRouter
from pydantic import BaseModel

from seed.run_seed import run_seed

router = APIRouter(prefix="/admin", tags=["Admin"])


class SeedResponse(BaseModel):
    message: str
    assets: int
    relationships: int
    vulnerabilities: int
    users: int


@router.post("/seed", response_model=SeedResponse)
def seed_database() -> SeedResponse:
    """Reset and load the synthetic Smart Hospital dataset."""
    summary = run_seed(reset=True)
    return SeedResponse(message="Smart Hospital dataset seeded", **summary)

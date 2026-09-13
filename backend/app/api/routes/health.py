"""Health / meta routes."""

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.common import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    db_kind = "sqlite" if settings.is_sqlite else "postgresql"
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.app_env,
        database=db_kind,
    )

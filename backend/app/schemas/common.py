"""Shared response schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    app: str
    environment: str
    database: str


class MessageResponse(BaseModel):
    message: str


class PlaceholderResponse(BaseModel):
    """Indicates a Phase 1 stub for engines implemented in later phases."""

    module: str
    status: str
    phase: str
    detail: str

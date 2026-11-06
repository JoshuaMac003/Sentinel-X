
"""Application settings loaded from environment variables."""

from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_BACKEND_DIR = Path(__file__).resolve().parents[2]
_REPO_ROOT = _BACKEND_DIR.parent

_ENV_CANDIDATES = (
    _REPO_ROOT / ".env",
    _BACKEND_DIR / ".env",
    Path(".env"),
)


class Settings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=tuple(
            str(p) for p in _ENV_CANDIDATES if p.exists()
        ) or (".env",),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SENTINEL-X"
    app_env: str = "development"
    app_debug: bool = True

    api_prefix: str = "/api"
    log_level: str = "INFO"

    database_url: str = "sqlite:///./data/sentinel_x.db"

    cors_origins: str = (
        "http://localhost:5173,"
        "http://127.0.0.1:5173"
    )

    # SDN monitoring configuration
    sdn_monitor_url: str = "http://172.17.61.217:8080"

    # Risk engine weights
    risk_weight_severity: float = Field(
        default=0.35, ge=0.0, le=1.0
    )
    risk_weight_exploitability: float = Field(
        default=0.25, ge=0.0, le=1.0
    )
    risk_weight_criticality: float = Field(
        default=0.25, ge=0.0, le=1.0
    )
    risk_weight_path: float = Field(
        default=0.15, ge=0.0, le=1.0
    )

    # Simulation engine weights
    sim_risk_weight_baseline: float = Field(
        default=0.55, ge=0.0, le=1.0
    )
    sim_risk_weight_impact: float = Field(
        default=0.45, ge=0.0, le=1.0
    )
    sim_min_exploitability: str = "LOW"

    @field_validator("api_prefix")
    @classmethod
    def normalize_api_prefix(cls, value: str) -> str:
        value = value.strip() or "/api"

        if not value.startswith("/"):
            value = f"/{value}"

        return value.rstrip("/") or "/api"

    @property
    def cors_origin_list(self) -> List[str]:
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()

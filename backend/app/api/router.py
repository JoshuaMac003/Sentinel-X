"""API router aggregation."""

from fastapi import APIRouter

from app.api.routes import (
    admin,
    assets,
    attack_graph,
    digital_twin,
    health,
    relationships,
    risk,
    simulations,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(admin.router)
api_router.include_router(assets.router)
api_router.include_router(relationships.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(digital_twin.router)
api_router.include_router(attack_graph.router)
api_router.include_router(risk.router)
api_router.include_router(simulations.router)

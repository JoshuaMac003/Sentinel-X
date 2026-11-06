
"""SENTINEL-X SDN monitoring API."""

import httpx
from fastapi import APIRouter, HTTPException

from app.core.config import get_settings

router = APIRouter(
    prefix="/sdn",
    tags=["SDN"]
)


@router.get("/monitor")
async def get_sdn_monitor():
    """Retrieve live switch and port statistics from OS-Ken."""

    settings = get_settings()
    monitor_url = settings.sdn_monitor_url.rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{monitor_url}/monitor/switches"
            )

        response.raise_for_status()

        return response.json()

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="SDN monitoring service timed out."
        )

    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"SDN monitoring service returned HTTP {exc.response.status_code}."
        )

    except httpx.RequestError:
        raise HTTPException(
            status_code=503,
            detail="Cannot connect to the SDN monitoring service."
        )

    except ValueError:
        raise HTTPException(
            status_code=502,
            detail="Invalid JSON received from SDN monitoring service."
        )

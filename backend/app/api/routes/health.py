"""Health and readiness probe endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.database import check_database_connectivity, get_db_session
from app.schemas.common import HealthResponse, ReadinessResponse
from app.security.authentication import resolve_settings

router = APIRouter(tags=["Health"])
logger = logging.getLogger("chaperone.health")


@router.get("/health", response_model=HealthResponse, summary="Liveness check")
async def health_check(settings: Settings = Depends(resolve_settings)) -> HealthResponse:
    """Return service liveness metadata without external dependencies."""
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version=settings.app_version,
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness check including database connectivity",
)
async def readiness_check(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> ReadinessResponse | JSONResponse:
    """Verify PostgreSQL connectivity before marking the gateway ready."""
    try:
        ok = await check_database_connectivity(session)
        if ok:
            return ReadinessResponse(
                status="ready",
                service=settings.app_name,
                database="connected",
            )
    except Exception:
        logger.warning("Readiness probe database check failed")

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "not_ready",
            "service": settings.app_name,
            "database": "unavailable",
        },
    )

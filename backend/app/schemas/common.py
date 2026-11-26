"""Common response envelopes, pagination helpers, error schemas, and health schemas."""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PaginatedResponse[T](BaseModel):
    """Standard paginated collection response envelope."""

    items: list[T]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    total_pages: int = Field(ge=0)

    @classmethod
    def create(
        cls,
        *,
        items: list[T],
        total: int,
        page: int,
        page_size: int,
    ) -> PaginatedResponse[T]:
        total_pages = math.ceil(total / page_size) if total > 0 else 0
        return cls(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )


class ErrorDetail(BaseModel):
    """Structured error body returned by centralized exception handlers."""

    code: str
    message: str
    correlation_id: str | None = None
    details: list[dict[str, Any]] | None = None


class ErrorResponse(BaseModel):
    """Top-level error envelope."""

    error: ErrorDetail


class HealthResponse(BaseModel):
    """Liveness probe response."""

    model_config = ConfigDict(frozen=True)

    status: str = "ok"
    service: str
    version: str


class ReadinessResponse(BaseModel):
    """Readiness probe response including database connectivity state."""

    model_config = ConfigDict(frozen=True)

    status: str
    service: str
    database: str

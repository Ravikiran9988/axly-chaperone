"""Correlation ID validation, generation, and propagation middleware."""

from __future__ import annotations

import re
import uuid

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.logging import correlation_id_var

_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Ensure every request carries a validated X-Correlation-ID header and log context."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        raw_header = request.headers.get("X-Correlation-ID")
        if raw_header is not None:
            candidate = raw_header.strip()
            if not _CORRELATION_ID_RE.fullmatch(candidate):
                fallback_id = str(uuid.uuid4())
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": {
                            "code": "INVALID_CORRELATION_ID",
                            "message": (
                                "X-Correlation-ID must be 8-64 characters of [A-Za-z0-9._-]."
                            ),
                            "correlation_id": fallback_id,
                        }
                    },
                    headers={"X-Correlation-ID": fallback_id},
                )
            correlation_id = candidate
        else:
            correlation_id = str(uuid.uuid4())

        request.state.correlation_id = correlation_id
        token = correlation_id_var.set(correlation_id)
        try:
            response = await call_next(request)
        finally:
            correlation_id_var.reset(token)

        response.headers["X-Correlation-ID"] = correlation_id
        return response

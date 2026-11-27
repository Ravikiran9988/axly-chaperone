"""HTTP request body size limit middleware to prevent oversized payload memory exhaustion."""

from __future__ import annotations

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import Settings


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject HTTP requests whose declared or streamed body exceeds max_request_body_bytes."""

    def __init__(self, app: object, *, settings: Settings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._max_bytes = settings.max_request_body_bytes

    def _too_large_response(self, request: Request) -> JSONResponse:
        correlation_id = getattr(request.state, "correlation_id", None)
        headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
        return JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": (
                        f"Request body exceeds maximum allowed size of {self._max_bytes} bytes."
                    ),
                    "correlation_id": correlation_id,
                }
            },
            headers=headers,
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_bytes:
                    return self._too_large_response(request)
            except ValueError:
                return self._too_large_response(request)

        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > self._max_bytes:
                return self._too_large_response(request)

        return await call_next(request)

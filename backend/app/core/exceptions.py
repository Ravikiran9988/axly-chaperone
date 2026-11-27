"""Domain exceptions and centralized FastAPI exception handlers."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import correlation_id_var, redact_secrets

logger = logging.getLogger("chaperone.exceptions")


class ChaperoneError(Exception):
    """Base application exception with structured code and HTTP status."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status_code: int,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.headers = headers


class AuthenticationError(ChaperoneError):
    """Raised when caller credentials are missing, malformed, or invalid."""

    def __init__(
        self, message: str = "Authentication required", code: str = "AUTHENTICATION_FAILED"
    ) -> None:
        super().__init__(message, code=code, status_code=status.HTTP_401_UNAUTHORIZED)


class AuthorizationError(ChaperoneError):
    """Raised when an authenticated principal is barred from performing an operation."""

    def __init__(self, message: str = "Forbidden", code: str = "FORBIDDEN") -> None:
        super().__init__(message, code=code, status_code=status.HTTP_403_FORBIDDEN)


class AdminBootstrapError(ChaperoneError):
    """Raised when administrative credentials have not been configured safely."""

    def __init__(
        self,
        message: str = "Administrative authentication is not configured.",
        code: str = "ADMIN_NOT_CONFIGURED",
    ) -> None:
        super().__init__(message, code=code, status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class ResourceNotFoundError(ChaperoneError):
    """Raised when a requested entity does not exist."""

    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND") -> None:
        super().__init__(message, code=code, status_code=status.HTTP_404_NOT_FOUND)


class ConflictError(ChaperoneError):
    """Raised when creating or updating an entity conflicts with unique constraints."""

    def __init__(self, message: str = "Resource already exists", code: str = "CONFLICT") -> None:
        super().__init__(message, code=code, status_code=status.HTTP_409_CONFLICT)


class BadRequestError(ChaperoneError):
    """Raised on semantic or security validation failures."""

    def __init__(self, message: str = "Invalid request", code: str = "BAD_REQUEST") -> None:
        super().__init__(message, code=code, status_code=status.HTTP_400_BAD_REQUEST)


class AuditPersistenceError(ChaperoneError):
    """Raised when an audit event fails to persist (fail-closed gateway invariant)."""

    def __init__(
        self,
        message: str = "Audit log persistence failed; request aborted.",
        code: str = "AUDIT_PERSISTENCE_ERROR",
    ) -> None:
        super().__init__(message, code=code, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RateLimitExceededError(ChaperoneError):
    """Raised when a caller exceeds the configured request rate limit."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            "Rate limit exceeded. Retry later.",
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after_seconds)},
        )


def _error_payload(
    *,
    code: str,
    message: str,
    correlation_id: str | None,
    details: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": correlation_id,
        }
    }
    if details is not None:
        payload["error"]["details"] = details
    return payload


def _get_correlation_id(request: Request) -> str | None:
    return getattr(request.state, "correlation_id", None) or correlation_id_var.get()


def register_exception_handlers(app: FastAPI) -> None:
    """Attach centralized, sanitized exception handlers to the FastAPI application."""

    @app.exception_handler(ChaperoneError)
    async def handle_chaperone_error(request: Request, exc: ChaperoneError) -> JSONResponse:
        correlation_id = _get_correlation_id(request)
        headers = dict(exc.headers) if exc.headers else {}
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                code=exc.code,
                message=redact_secrets(exc.message),
                correlation_id=correlation_id,
            ),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request,
        exc: RequestValidationError,
    ) -> JSONResponse:
        correlation_id = _get_correlation_id(request)
        sanitized_details: list[dict[str, Any]] = []
        for err in exc.errors():
            sanitized_details.append(
                {
                    "loc": [str(part) for part in err.get("loc", ())],
                    "msg": redact_secrets(str(err.get("msg", "Invalid value"))),
                    "type": str(err.get("type", "value_error")),
                }
            )
        headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=_error_payload(
                code="VALIDATION_ERROR",
                message="Request validation failed.",
                correlation_id=correlation_id,
                details=sanitized_details,
            ),
            headers=headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request,
        exc: StarletteHTTPException,
    ) -> JSONResponse:
        correlation_id = _get_correlation_id(request)
        headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                code="HTTP_ERROR",
                message=redact_secrets(str(exc.detail)) if exc.detail else "HTTP error",
                correlation_id=correlation_id,
            ),
            headers=headers,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        correlation_id = _get_correlation_id(request)
        logger.exception("Unhandled server exception on path=%s", request.url.path)
        headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_payload(
                code="INTERNAL_ERROR",
                message="An internal security gateway error occurred.",
                correlation_id=correlation_id,
            ),
            headers=headers,
        )

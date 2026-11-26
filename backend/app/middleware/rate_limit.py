"""In-memory sliding-window rate limiting middleware for Phase 1 single-process protection."""

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import Settings
from app.core.security import parse_agent_api_key


class InMemorySlidingWindowLimiter:
    """Thread-safe sliding window rate limiter keyed by credential identifier or client IP."""

    def __init__(self, *, max_requests: int, window_seconds: int) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check_and_consume(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._max_requests:
                retry_after = max(1, math.ceil(bucket[0] + self._window_seconds - now))
                return False, retry_after
            bucket.append(now)
            return True, 0


def _derive_rate_limit_key(request: Request) -> str:
    agent_key = request.headers.get("X-Agent-Key")
    if agent_key:
        parsed = parse_agent_api_key(agent_key)
        if parsed is not None:
            return f"agent:{parsed[0]}"
        digest = hashlib.sha256(agent_key.encode("utf-8")).hexdigest()[:16]
        return f"agent_raw:{digest}"

    admin_key = request.headers.get("X-Admin-Key")
    if admin_key:
        digest = hashlib.sha256(admin_key.encode("utf-8")).hexdigest()[:16]
        return f"admin:{digest}"

    client_host = request.client.host if request.client else "unknown"
    return f"ip:{client_host}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply Phase 1 rate limiting to API routes (health/readiness probes excluded)."""

    def __init__(self, app: object, *, settings: Settings) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._enabled = settings.rate_limit_enabled
        self._limiter = InMemorySlidingWindowLimiter(
            max_requests=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        if not self._enabled or request.url.path in {"/health", "/ready"}:
            return await call_next(request)

        bucket_key = _derive_rate_limit_key(request)
        allowed, retry_after = self._limiter.check_and_consume(bucket_key)
        if not allowed:
            correlation_id = getattr(request.state, "correlation_id", None)
            headers = {"Retry-After": str(retry_after)}
            if correlation_id:
                headers["X-Correlation-ID"] = correlation_id
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": "Rate limit exceeded. Retry later.",
                        "correlation_id": correlation_id,
                    }
                },
                headers=headers,
            )
        return await call_next(request)

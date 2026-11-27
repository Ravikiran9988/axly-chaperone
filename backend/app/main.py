"""FastAPI application factory for AXLY Chaperone."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.routes import agents, approvals, audit, gateway, health, policies, tools
from app.core.config import Settings, get_settings
from app.core.database import build_engine, build_session_factory
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.middleware.correlation import CorrelationIdMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware


def create_app(
    settings: Settings | None = None,
    *,
    engine: AsyncEngine | None = None,
) -> FastAPI:
    """Create and configure a modular AXLY Chaperone FastAPI application instance."""
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configure_logging(
            level=resolved_settings.log_level,
            json_logs=resolved_settings.log_json,
        )
        owns_engine = engine is None
        db_engine = engine or build_engine(
            resolved_settings.database_url,
            echo=resolved_settings.db_echo,
            pool_size=resolved_settings.db_pool_size,
            max_overflow=resolved_settings.db_max_overflow,
        )
        application.state.settings = resolved_settings
        application.state.engine = db_engine
        application.state.session_factory = build_session_factory(db_engine)
        try:
            yield
        finally:
            if owns_engine:
                await db_engine.dispose()

    application = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        description=(
            "AXLY Chaperone — AI Agent Security & Governance Gateway (Phase 1). "
            "Safe autonomy. Human control."
        ),
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings

    # Middleware execution order is outer-to-inner (last added runs first):
    # CorrelationId -> SecurityHeaders -> RateLimit -> CORS -> Route
    if resolved_settings.cors_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=resolved_settings.cors_origins,
            allow_credentials=False,
            allow_methods=resolved_settings.cors_allow_methods,
            allow_headers=resolved_settings.cors_allow_headers,
        )
    application.add_middleware(RateLimitMiddleware, settings=resolved_settings)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(CorrelationIdMiddleware)

    register_exception_handlers(application)

    application.include_router(health.router)
    application.include_router(agents.router)
    application.include_router(tools.router)
    application.include_router(policies.router)
    application.include_router(approvals.router)
    application.include_router(audit.router)
    application.include_router(gateway.router)

    return application


app = create_app()

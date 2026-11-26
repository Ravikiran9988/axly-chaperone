"""Authentication dependencies for administrative principals and AI agents."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.core.exceptions import AdminBootstrapError, AuthenticationError
from app.core.security import (
    dummy_verify_api_key,
    parse_agent_api_key,
    verify_admin_key,
    verify_api_key,
)
from app.models.agent import Agent
from app.models.enums import AgentStatus, VerificationStatus


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Verified administrative caller context."""

    authenticated: bool = True
    auth_scheme: str = "x-admin-key"


@dataclass(frozen=True, slots=True)
class AgentAuthResult:
    """Outcome of agent API key verification (supports audit logging on failure)."""

    authenticated: bool
    agent: Agent | None
    verification_status: VerificationStatus
    failure_reason: str | None = None


def resolve_settings(request: Request) -> Settings:
    """Resolve app-scoped settings if attached to state, else fallback to cached settings."""
    app_settings: Settings | None = getattr(request.app.state, "settings", None)
    return app_settings if app_settings is not None else get_settings()


async def authenticate_admin(
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
    settings: Settings = Depends(resolve_settings),
) -> AdminPrincipal:
    """Authenticate an administrative request via the X-Admin-Key header."""
    configured_key = settings.get_admin_api_key()
    if configured_key is None:
        raise AdminBootstrapError(
            "Administrative API key is not configured. Set CHAPERONE_ADMIN_API_KEY before use."
        )
    if not x_admin_key:
        raise AuthenticationError(
            "Missing X-Admin-Key header.",
            code="ADMIN_AUTH_REQUIRED",
        )
    if not verify_admin_key(x_admin_key, configured_key):
        raise AuthenticationError(
            "Invalid administrative credentials.",
            code="INVALID_ADMIN_CREDENTIALS",
        )
    return AdminPrincipal()


async def authenticate_agent_key(
    raw_key: str | None,
    *,
    session: AsyncSession,
    settings: Settings,
) -> AgentAuthResult:
    """Verify an agent's X-Agent-Key credential without leaking timing or existence."""
    if not raw_key or not raw_key.strip():
        return AgentAuthResult(
            authenticated=False,
            agent=None,
            verification_status=VerificationStatus.UNAUTHENTICATED,
            failure_reason="Missing X-Agent-Key header.",
        )

    parsed = parse_agent_api_key(raw_key)
    pepper = settings.get_api_key_pepper()
    if parsed is None:
        dummy_verify_api_key(iterations=settings.api_key_hash_iterations, pepper=pepper)
        return AgentAuthResult(
            authenticated=False,
            agent=None,
            verification_status=VerificationStatus.INVALID_CREDENTIALS,
            failure_reason="Invalid agent API key.",
        )

    key_id, _ = parsed
    stmt = select(Agent).where(Agent.key_id == key_id)
    result = await session.execute(stmt)
    agent = result.scalar_one_or_none()

    if agent is None:
        dummy_verify_api_key(iterations=settings.api_key_hash_iterations, pepper=pepper)
        return AgentAuthResult(
            authenticated=False,
            agent=None,
            verification_status=VerificationStatus.INVALID_CREDENTIALS,
            failure_reason="Invalid agent API key.",
        )

    if not verify_api_key(raw_key.strip(), agent.api_key_hash, pepper=pepper):
        return AgentAuthResult(
            authenticated=False,
            agent=None,
            verification_status=VerificationStatus.INVALID_CREDENTIALS,
            failure_reason="Invalid agent API key.",
        )

    if agent.status != AgentStatus.ACTIVE.value:
        return AgentAuthResult(
            authenticated=False,
            agent=agent,
            verification_status=VerificationStatus.AGENT_DISABLED,
            failure_reason="Agent account is disabled.",
        )

    return AgentAuthResult(
        authenticated=True,
        agent=agent,
        verification_status=VerificationStatus.VERIFIED,
    )


async def get_agent_auth_result(
    x_agent_key: str | None = Header(default=None, alias="X-Agent-Key"),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AgentAuthResult:
    """FastAPI dependency returning structured AgentAuthResult for audited gateway enforcement."""
    return await authenticate_agent_key(x_agent_key, session=session, settings=settings)

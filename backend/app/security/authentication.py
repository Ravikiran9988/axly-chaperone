"""Authentication dependencies for administrative principals and AI agents."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session
from app.core.exceptions import AdminBootstrapError, AuthenticationError, AuthorizationError
from app.core.security import (
    dummy_verify_api_key,
    hash_session_token,
    parse_agent_api_key,
    verify_admin_key,
    verify_api_key,
)
from app.models.admin import AdminSession, AdminUser
from app.models.agent import Agent
from app.models.enums import AdminRole, AdminStatus, AgentStatus, VerificationStatus

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Verified administrative caller context (derived exclusively server-side)."""

    authenticated: bool = True
    auth_scheme: str = "session_cookie"
    reviewer_id: str = "admin"
    role: AdminRole = AdminRole.SUPER_ADMIN
    user_id: UUID | None = None
    session_id: UUID | None = None
    csrf_token: str | None = None
    expires_at: datetime | None = None


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
    request: Request,
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AdminPrincipal:
    """Authenticate an administrative request via HttpOnly session cookie (or dev X-Admin-Key).

    Security invariant: client-supplied actor identity headers (such as X-Admin-Actor) are never
    read or trusted; reviewer_id is always derived exclusively from verified server state.
    """
    raw_session_token = request.cookies.get(settings.session_cookie_name)
    if raw_session_token:
        token_hash = hash_session_token(raw_session_token)
        session_row = (
            await session.execute(select(AdminSession).where(AdminSession.token_hash == token_hash))
        ).scalar_one_or_none()
        if session_row is None:
            raise AuthenticationError(
                "Invalid administrative session.",
                code="INVALID_SESSION",
            )
        if session_row.revoked_at is not None:
            raise AuthenticationError(
                "Administrative session has been revoked.",
                code="SESSION_REVOKED",
            )
        expires_at = (
            session_row.expires_at.replace(tzinfo=UTC)
            if session_row.expires_at.tzinfo is None
            else session_row.expires_at.astimezone(UTC)
        )
        if datetime.now(UTC) >= expires_at:
            raise AuthenticationError(
                "Administrative session has expired.",
                code="SESSION_EXPIRED",
            )

        if request.method.upper() not in _SAFE_METHODS:
            if not x_csrf_token or not hmac.compare_digest(
                x_csrf_token.strip(), session_row.csrf_token
            ):
                raise AuthorizationError(
                    "Invalid or missing CSRF token.",
                    code="CSRF_VALIDATION_FAILED",
                )

        if session_row.admin_user_id is not None:
            user = (
                await session.execute(
                    select(AdminUser).where(AdminUser.id == session_row.admin_user_id)
                )
            ).scalar_one_or_none()
            if user is None or user.status != AdminStatus.ACTIVE.value:
                raise AuthenticationError(
                    "Administrator account is inactive or no longer exists.",
                    code="ADMIN_ACCOUNT_DISABLED",
                )
            reviewer_id = user.username
            role = AdminRole(user.role)
        else:
            reviewer_id = session_row.principal_id
            role = AdminRole(session_row.role)

        return AdminPrincipal(
            authenticated=True,
            auth_scheme="session_cookie",
            reviewer_id=reviewer_id,
            role=role,
            user_id=session_row.admin_user_id,
            session_id=session_row.id,
            csrf_token=session_row.csrf_token,
            expires_at=expires_at,
        )

    configured_key = settings.get_admin_api_key()
    if x_admin_key is not None:
        if configured_key is None:
            raise AdminBootstrapError(
                "Administrative API key is not configured. Set CHAPERONE_ADMIN_API_KEY before use."
            )
        if not settings.allow_admin_api_key_header:
            raise AuthorizationError(
                "Header-based X-Admin-Key access is disabled; sign in using session cookies.",
                code="ADMIN_KEY_HEADER_DISABLED",
            )
        if not verify_admin_key(x_admin_key, configured_key):
            raise AuthenticationError(
                "Invalid administrative credentials.",
                code="INVALID_ADMIN_CREDENTIALS",
            )
        key_fingerprint = hashlib.sha256(configured_key.encode("utf-8")).hexdigest()[:12]
        return AdminPrincipal(
            authenticated=True,
            auth_scheme="x-admin-key",
            reviewer_id=f"admin:{key_fingerprint}",
            role=AdminRole.SUPER_ADMIN,
        )

    if configured_key is None:
        any_admin = (
            await session.execute(
                select(AdminUser.id).where(AdminUser.status == AdminStatus.ACTIVE.value).limit(1)
            )
        ).scalar_one_or_none()
        if any_admin is None:
            raise AdminBootstrapError(
                "Administrative authentication is not configured. "
                "Create an admin user or set CHAPERONE_ADMIN_API_KEY."
            )

    raise AuthenticationError(
        "Administrative authentication required.",
        code="ADMIN_AUTH_REQUIRED",
    )


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

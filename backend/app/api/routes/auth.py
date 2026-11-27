"""Server-managed administrator session authentication and RBAC user endpoints."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.database import get_db_session
from app.core.exceptions import (
    AdminBootstrapError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ResourceNotFoundError,
)
from app.core.security import (
    dummy_verify_password,
    generate_csrf_token,
    generate_session_token,
    hash_password,
    hash_session_token,
    verify_admin_key,
    verify_password,
)
from app.models.admin import AdminSession, AdminUser
from app.models.enums import AdminRole, AdminStatus
from app.schemas.auth import (
    AdminLoginRequest,
    AdminLogoutResponse,
    AdminSessionResponse,
    AdminUserCreateRequest,
    AdminUserResponse,
    AdminUserStatusUpdateRequest,
)
from app.security.authentication import AdminPrincipal, resolve_settings
from app.security.authorization import require_admin, require_super_admin

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _set_auth_cookies(
    response: Response,
    *,
    raw_session_token: str,
    csrf_token: str,
    settings: Settings,
) -> None:
    secure = settings.resolve_cookie_secure()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_session_token,
        max_age=settings.admin_session_ttl_seconds,
        httponly=True,
        secure=secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=settings.admin_session_ttl_seconds,
        httponly=False,
        secure=secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


def _clear_auth_cookies(response: Response, *, settings: Settings) -> None:
    secure = settings.resolve_cookie_secure()
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=secure,
        samesite=settings.cookie_samesite,
    )
    response.delete_cookie(
        key=settings.csrf_cookie_name,
        path="/",
        httponly=False,
        secure=secure,
        samesite=settings.cookie_samesite,
    )


@router.post(
    "/login",
    response_model=AdminSessionResponse,
    summary="Authenticate administrator and issue HttpOnly session cookie",
)
async def login_admin(
    payload: AdminLoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AdminSessionResponse:
    """Issue a short-lived HttpOnly cookie session and bound CSRF token."""
    pepper = settings.get_api_key_pepper()
    admin_user_id: UUID | None = None
    principal_id: str
    role: AdminRole

    if payload.username is not None and payload.password is not None:
        user = (
            await session.execute(select(AdminUser).where(AdminUser.username == payload.username))
        ).scalar_one_or_none()
        if user is None:
            dummy_verify_password(iterations=settings.api_key_hash_iterations, pepper=pepper)
            raise AuthenticationError(
                "Invalid administrator username or password.",
                code="INVALID_ADMIN_CREDENTIALS",
            )
        if not verify_password(payload.password, user.password_hash, pepper=pepper):
            raise AuthenticationError(
                "Invalid administrator username or password.",
                code="INVALID_ADMIN_CREDENTIALS",
            )
        if user.status != AdminStatus.ACTIVE.value:
            raise AuthorizationError(
                "Administrator account is disabled.",
                code="ADMIN_ACCOUNT_DISABLED",
            )
        admin_user_id = user.id
        principal_id = user.username
        role = AdminRole(user.role)
    else:
        assert payload.admin_key is not None
        if not settings.allow_bootstrap_key_login:
            raise AuthorizationError(
                "Bootstrap key session login is disabled; authenticate with username and password.",
                code="BOOTSTRAP_LOGIN_DISABLED",
            )
        configured_key = settings.get_admin_api_key()
        if configured_key is None:
            raise AdminBootstrapError(
                "Administrative bootstrap key is not configured.",
            )
        if not verify_admin_key(payload.admin_key.strip(), configured_key):
            raise AuthenticationError(
                "Invalid administrative credentials.",
                code="INVALID_ADMIN_CREDENTIALS",
            )
        key_fingerprint = hashlib.sha256(configured_key.encode("utf-8")).hexdigest()[:12]
        principal_id = f"bootstrap-admin:{key_fingerprint}"
        role = AdminRole.SUPER_ADMIN

    raw_session_token = generate_session_token()
    csrf_token = generate_csrf_token()
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=settings.admin_session_ttl_seconds)

    session_row = AdminSession(
        admin_user_id=admin_user_id,
        principal_id=principal_id,
        role=role.value,
        token_hash=hash_session_token(raw_session_token),
        csrf_token=csrf_token,
        auth_scheme="session_cookie",
        expires_at=expires_at,
        created_at=now,
    )
    session.add(session_row)
    await session.commit()

    _set_auth_cookies(
        response,
        raw_session_token=raw_session_token,
        csrf_token=csrf_token,
        settings=settings,
    )
    return AdminSessionResponse(
        authenticated=True,
        auth_scheme="session_cookie",
        reviewer_id=principal_id,
        role=role,
        csrf_token=csrf_token,
        expires_at=expires_at,
    )


@router.get(
    "/session",
    response_model=AdminSessionResponse,
    summary="Inspect active verified administrator session",
)
async def get_current_session(
    principal: AdminPrincipal = Depends(require_admin),
) -> AdminSessionResponse:
    """Return the verified server-side administrator identity and role."""
    return AdminSessionResponse(
        authenticated=True,
        auth_scheme=principal.auth_scheme,
        reviewer_id=principal.reviewer_id,
        role=principal.role,
        csrf_token=principal.csrf_token,
        expires_at=principal.expires_at,
    )


@router.post(
    "/logout",
    response_model=AdminLogoutResponse,
    summary="Revoke active session and clear authentication cookies",
)
async def logout_admin(
    response: Response,
    principal: AdminPrincipal = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AdminLogoutResponse:
    """Revoke server-side session token immediately and clear browser cookies."""
    if principal.session_id is not None:
        row = (
            await session.execute(
                select(AdminSession).where(AdminSession.id == principal.session_id)
            )
        ).scalar_one_or_none()
        if row is not None and row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
            await session.commit()

    _clear_auth_cookies(response, settings=settings)
    return AdminLogoutResponse(logged_out=True)


@router.post(
    "/users",
    response_model=AdminUserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an individual administrator user account",
)
async def create_admin_user(
    payload: AdminUserCreateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> AdminUserResponse:
    """Register a named admin principal with PBKDF2-HMAC-SHA256 credentials and RBAC role."""
    existing = (
        await session.execute(select(AdminUser).where(AdminUser.username == payload.username))
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"Admin user '{payload.username}' already exists.")

    user = AdminUser(
        username=payload.username,
        password_hash=hash_password(
            payload.password,
            iterations=settings.api_key_hash_iterations,
            pepper=settings.get_api_key_pepper(),
        ),
        role=payload.role.value,
        status=AdminStatus.ACTIVE.value,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return AdminUserResponse.model_validate(user)


@router.get(
    "/users",
    response_model=list[AdminUserResponse],
    summary="List administrator user accounts",
)
async def list_admin_users(
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> list[AdminUserResponse]:
    """List administrator accounts without exposing password hashes."""
    users = (
        (await session.execute(select(AdminUser).order_by(AdminUser.username.asc())))
        .scalars()
        .all()
    )
    return [AdminUserResponse.model_validate(u) for u in users]


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserResponse,
    summary="Update administrator account role or status",
)
async def update_admin_user(
    user_id: UUID,
    payload: AdminUserStatusUpdateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> AdminUserResponse:
    """Enable/disable an administrator account or adjust its RBAC role."""
    user = (
        await session.execute(select(AdminUser).where(AdminUser.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        raise ResourceNotFoundError(f"Admin user '{user_id}' not found.")
    if payload.status is not None:
        user.status = payload.status.value
    if payload.role is not None:
        user.role = payload.role.value
    await session.commit()
    await session.refresh(user)
    return AdminUserResponse.model_validate(user)

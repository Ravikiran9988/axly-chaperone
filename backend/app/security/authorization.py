"""Authorization and RBAC separation dependencies for control-plane and gateway endpoints."""

from __future__ import annotations

from fastapi import Depends

from app.core.exceptions import AuthenticationError, AuthorizationError
from app.models.enums import AdminRole, VerificationStatus
from app.security.authentication import AdminPrincipal, AgentAuthResult, authenticate_admin


async def require_admin(
    principal: AdminPrincipal = Depends(authenticate_admin),
) -> AdminPrincipal:
    """Enforce authenticated administrative identity (viewer, approver, or super_admin)."""
    if not principal.authenticated:
        raise AuthorizationError("Administrative access required.")
    return principal


async def require_approver(
    principal: AdminPrincipal = Depends(require_admin),
) -> AdminPrincipal:
    """Enforce approval authority (approver or super_admin role required)."""
    if principal.role not in {AdminRole.APPROVER, AdminRole.SUPER_ADMIN}:
        raise AuthorizationError(
            "Role 'approver' or 'super_admin' is required for approval decisions.",
            code="INSUFFICIENT_ROLE",
        )
    return principal


async def require_super_admin(
    principal: AdminPrincipal = Depends(require_admin),
) -> AdminPrincipal:
    """Enforce full administrative authority (super_admin role required)."""
    if principal.role != AdminRole.SUPER_ADMIN:
        raise AuthorizationError(
            "Role 'super_admin' is required for administrative configuration changes.",
            code="INSUFFICIENT_ROLE",
        )
    return principal


def enforce_agent_access(auth_result: AgentAuthResult) -> None:
    """Raise appropriate 401 or 403 exception when agent auth fails or agent is disabled."""
    if auth_result.authenticated and auth_result.agent is not None:
        return
    if auth_result.verification_status == VerificationStatus.AGENT_DISABLED:
        raise AuthorizationError(
            auth_result.failure_reason or "Agent is disabled.",
            code="AGENT_DISABLED",
        )
    raise AuthenticationError(
        auth_result.failure_reason or "Invalid or missing agent API key.",
        code="INVALID_AGENT_CREDENTIALS",
    )

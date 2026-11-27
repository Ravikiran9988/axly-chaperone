"""Administrative API endpoints for authorization policies."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.models.enums import PolicyDecision
from app.schemas.common import PaginatedResponse
from app.schemas.policy import PolicyCreateRequest, PolicyResponse, PolicyUpdateRequest
from app.security.authentication import AdminPrincipal
from app.security.authorization import require_admin, require_super_admin
from app.services.policy_service import PolicyService

router = APIRouter(
    prefix="/api/v1/policies",
    tags=["Policies"],
    dependencies=[Depends(require_admin)],
)
_policy_service = PolicyService()


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an authorization policy",
)
async def create_policy(
    payload: PolicyCreateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> PolicyResponse:
    """Create a deterministic policy evaluated by the Chaperone policy engine."""
    policy = await _policy_service.create_policy(session, payload)
    return PolicyResponse.model_validate(policy)


@router.get(
    "",
    response_model=PaginatedResponse[PolicyResponse],
    summary="List authorization policies",
)
async def list_policies(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    agent_id: UUID | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    decision: PolicyDecision | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[PolicyResponse]:
    """List authorization policies ordered by priority descending."""
    items, total = await _policy_service.list_policies(
        session,
        page=page,
        page_size=page_size,
        agent_id=agent_id,
        tool_name=tool_name,
        decision=decision,
        enabled=enabled,
    )
    return PaginatedResponse.create(
        items=[PolicyResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Get a policy by ID",
)
async def get_policy(
    policy_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> PolicyResponse:
    """Retrieve a single authorization policy by UUID."""
    policy = await _policy_service.get_policy(session, policy_id)
    return PolicyResponse.model_validate(policy)


@router.patch(
    "/{policy_id}",
    response_model=PolicyResponse,
    summary="Update a policy (increments policy version)",
)
async def update_policy(
    policy_id: UUID,
    payload: PolicyUpdateRequest,
    _principal: AdminPrincipal = Depends(require_super_admin),
    session: AsyncSession = Depends(get_db_session),
) -> PolicyResponse:
    """Update mutable properties on a policy and increment its version."""
    policy = await _policy_service.update_policy(session, policy_id, payload)
    return PolicyResponse.model_validate(policy)

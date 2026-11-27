"""Administrative API endpoints for the Human-in-the-Loop Approval workflow."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.approvals.schemas import (
    ApprovalActionResponse,
    ApprovalDecisionRequest,
    ApprovalRejectRequest,
    ApprovalResponse,
)
from app.approvals.service import ApprovalService
from app.core.config import Settings
from app.core.database import get_db_session
from app.models.enums import ApprovalStatus
from app.schemas.common import PaginatedResponse
from app.security.authentication import AdminPrincipal, resolve_settings
from app.security.authorization import require_admin, require_approver

router = APIRouter(
    prefix="/api/v1/approvals",
    tags=["Approvals"],
    dependencies=[Depends(require_admin)],
)
_approval_service = ApprovalService()


@router.get(
    "",
    response_model=PaginatedResponse[ApprovalResponse],
    summary="List human approval requests",
)
async def list_approvals(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: ApprovalStatus | None = Query(default=None, alias="status"),
    agent_id: UUID | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[ApprovalResponse]:
    """List approval requests with pagination and optional status/agent/tool filters."""
    items, total = await _approval_service.list_approvals(
        session,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        agent_id=agent_id,
        tool_name=tool_name,
    )
    return PaginatedResponse.create(
        items=[ApprovalResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{approval_id}",
    response_model=ApprovalResponse,
    summary="Get an approval request by ID",
)
async def get_approval(
    approval_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> ApprovalResponse:
    """Retrieve details for a specific approval request."""
    approval = await _approval_service.get_approval(session, approval_id)
    return ApprovalResponse.model_validate(approval)


@router.post(
    "/{approval_id}/approve",
    response_model=ApprovalActionResponse,
    summary="Approve a pending tool execution request",
)
async def approve_request(
    approval_id: UUID,
    payload: ApprovalDecisionRequest | None = Body(default=None),
    principal: AdminPrincipal = Depends(require_approver),
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(resolve_settings),
) -> ApprovalActionResponse:
    """Approve a pending request (and execute + independently verify once by default)."""
    decision_body = payload or ApprovalDecisionRequest()
    approval, verification, output = await _approval_service.approve(
        session,
        approval_id=approval_id,
        reviewer_id=principal.reviewer_id,
        comment=decision_body.comment,
        execute_now=decision_body.execute_now,
        settings=settings,
    )
    verification_payload = (
        {
            "verification_id": str(verification.verification_id),
            "status": verification.status.value.upper(),
            "method": verification.method,
            "message": verification.message,
        }
        if verification is not None
        else None
    )
    exec_status = (
        "EXECUTED"
        if approval.status == ApprovalStatus.EXECUTED.value
        else "FAILED"
        if approval.status == ApprovalStatus.FAILED.value
        else "APPROVED"
    )
    return ApprovalActionResponse(
        approval=ApprovalResponse.model_validate(approval),
        execution_status=exec_status,
        output=output,
        verification=verification_payload,
    )


@router.post(
    "/{approval_id}/reject",
    response_model=ApprovalActionResponse,
    summary="Reject a pending tool execution request",
)
async def reject_request(
    approval_id: UUID,
    payload: ApprovalRejectRequest | None = Body(default=None),
    principal: AdminPrincipal = Depends(require_approver),
    session: AsyncSession = Depends(get_db_session),
) -> ApprovalActionResponse:
    """Reject a pending request (the tool is never executed)."""
    reject_body = payload or ApprovalRejectRequest()
    approval = await _approval_service.reject(
        session,
        approval_id=approval_id,
        reviewer_id=principal.reviewer_id,
        comment=reject_body.comment,
    )
    return ApprovalActionResponse(
        approval=ApprovalResponse.model_validate(approval),
        execution_status="REJECTED",
    )

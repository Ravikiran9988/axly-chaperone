"""Read-only administrative API endpoints for append-only audit events."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.models.enums import AuditEventType, PolicyDecision, VerificationStatus
from app.schemas.audit import AuditEventResponse, AuditIntegrityResponse
from app.schemas.common import PaginatedResponse
from app.security.authorization import require_admin
from app.services.audit_service import AuditService

router = APIRouter(
    prefix="/api/v1/audit-events",
    tags=["Audit Events"],
    dependencies=[Depends(require_admin)],
)
_audit_service = AuditService()


@router.get(
    "",
    response_model=PaginatedResponse[AuditEventResponse],
    summary="List immutable gateway audit events",
)
async def list_audit_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    agent_id: UUID | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    decision: PolicyDecision | None = Query(default=None),
    correlation_id: str | None = Query(default=None),
    verification_status: VerificationStatus | None = Query(default=None),
    event_type: AuditEventType | None = Query(default=None),
    approval_id: UUID | None = Query(default=None),
    order: Literal["asc", "desc"] = Query(default="desc"),
    session: AsyncSession = Depends(get_db_session),
) -> PaginatedResponse[AuditEventResponse]:
    """Query append-only gateway audit records (update/delete are intentionally unavailable)."""
    items, total = await _audit_service.list_events(
        session,
        page=page,
        page_size=page_size,
        agent_id=agent_id,
        tool_name=tool_name,
        decision=decision,
        correlation_id=correlation_id,
        verification_status=verification_status,
        event_type=event_type,
        approval_id=approval_id,
        order=order,
    )
    return PaginatedResponse.create(
        items=[AuditEventResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/integrity",
    response_model=AuditIntegrityResponse,
    summary="Verify cryptographic digest integrity of audit events",
)
async def verify_audit_integrity(
    limit: int = Query(default=500, ge=1, le=5000),
    session: AsyncSession = Depends(get_db_session),
) -> AuditIntegrityResponse:
    """Recompute SHA-256 record digests across stored audit logs to detect tampering."""
    result = await _audit_service.verify_integrity(session, limit=limit)
    return AuditIntegrityResponse.model_validate(result)


@router.get(
    "/{event_id}",
    response_model=AuditEventResponse,
    summary="Get a single audit event",
)
async def get_audit_event(
    event_id: UUID,
    session: AsyncSession = Depends(get_db_session),
) -> AuditEventResponse:
    """Retrieve an immutable audit record by UUID."""
    event = await _audit_service.get_event(session, event_id)
    return AuditEventResponse.model_validate(event)

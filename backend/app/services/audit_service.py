"""Append-only audit logging service with fail-closed persistence guarantees."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuditPersistenceError, ResourceNotFoundError
from app.core.logging import redact_secrets
from app.models.audit import AuditEvent
from app.models.enums import ExecutionStatus, PolicyDecision, VerificationStatus

logger = logging.getLogger("chaperone.audit")


class AuditService:
    """Append-only audit service. Exposes creation and read queries only (never update/delete)."""

    async def record_event(
        self,
        session: AsyncSession,
        *,
        correlation_id: str,
        agent_id: UUID | None,
        tool_name: str,
        action: str,
        resource: str,
        decision: PolicyDecision,
        reason: str,
        policy_id: UUID | None,
        policy_version: int | None,
        policy_metadata: dict[str, Any] | None,
        execution_status: ExecutionStatus,
        verification_status: VerificationStatus,
    ) -> AuditEvent:
        """Persist an immutable audit event; fail closed if persistence fails."""
        safe_resource = redact_secrets(resource)[:1024]
        safe_reason = redact_secrets(reason)[:2000]
        event = AuditEvent(
            correlation_id=correlation_id[:64],
            agent_id=agent_id,
            tool_name=tool_name[:128],
            action=action[:64],
            resource=safe_resource,
            decision=decision.value,
            reason=safe_reason,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_metadata=policy_metadata,
            execution_status=execution_status.value,
            verification_status=verification_status.value,
        )
        session.add(event)
        try:
            await session.commit()
            await session.refresh(event)
        except SQLAlchemyError as exc:
            await session.rollback()
            logger.error(
                "Audit persistence failed; failing closed",
                extra={"correlation_id": correlation_id},
            )
            raise AuditPersistenceError() from exc
        return event

    async def list_events(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        agent_id: UUID | None = None,
        tool_name: str | None = None,
        decision: PolicyDecision | None = None,
        correlation_id: str | None = None,
        verification_status: VerificationStatus | None = None,
    ) -> tuple[list[AuditEvent], int]:
        """List audit events in reverse chronological order with pagination and filters."""
        filters = []
        if agent_id is not None:
            filters.append(AuditEvent.agent_id == agent_id)
        if tool_name is not None:
            filters.append(AuditEvent.tool_name == tool_name.strip().lower())
        if decision is not None:
            filters.append(AuditEvent.decision == decision.value)
        if correlation_id is not None:
            filters.append(AuditEvent.correlation_id == correlation_id.strip())
        if verification_status is not None:
            filters.append(AuditEvent.verification_status == verification_status.value)

        count_stmt = select(func.count()).select_from(AuditEvent).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        stmt = (
            select(AuditEvent)
            .where(*filters)
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_event(self, session: AsyncSession, event_id: UUID) -> AuditEvent:
        """Retrieve a single audit event by UUID."""
        stmt = select(AuditEvent).where(AuditEvent.id == event_id)
        event = (await session.execute(stmt)).scalar_one_or_none()
        if event is None:
            raise ResourceNotFoundError(f"Audit event '{event_id}' not found.")
        return event

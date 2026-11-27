"""Append-only audit logging service with fail-closed persistence guarantees."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuditPersistenceError, ResourceNotFoundError
from app.core.logging import redact_secrets
from app.models.audit import AuditEvent
from app.models.enums import AuditEventType, ExecutionStatus, PolicyDecision, VerificationStatus

logger = logging.getLogger("chaperone.audit")


def _fmt_utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return aware.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_audit_record_hash(event: AuditEvent) -> str:
    """Compute a deterministic SHA-256 digest over immutable AuditEvent fields."""
    canonical = json.dumps(
        {
            "id": str(event.id),
            "event_type": event.event_type,
            "correlation_id": event.correlation_id,
            "agent_id": str(event.agent_id) if event.agent_id else None,
            "tool_name": event.tool_name,
            "action": event.action,
            "resource": event.resource,
            "decision": event.decision,
            "reason": event.reason,
            "policy_id": str(event.policy_id) if event.policy_id else None,
            "policy_version": event.policy_version,
            "approval_id": str(event.approval_id) if event.approval_id else None,
            "reviewer_id": event.reviewer_id,
            "reviewed_at": _fmt_utc_iso(event.reviewed_at),
            "verification_outcome": event.verification_outcome,
            "execution_status": event.execution_status,
            "verification_status": event.verification_status,
            "created_at": _fmt_utc_iso(event.created_at),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
        event_type: AuditEventType = AuditEventType.POLICY_EVALUATION,
        approval_id: UUID | None = None,
        reviewer_id: str | None = None,
        reviewed_at: datetime | None = None,
        verification_outcome: str | None = None,
        execution_metadata: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditEvent:
        """Persist an immutable audit event with integrity digest; fail closed on error."""
        safe_resource = redact_secrets(resource)[:1024]
        safe_reason = redact_secrets(reason)[:2000]
        event_id = uuid.uuid4()
        created_at = datetime.now(UTC)
        event = AuditEvent(
            id=event_id,
            event_type=event_type.value,
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
            approval_id=approval_id,
            reviewer_id=reviewer_id[:128] if reviewer_id else None,
            reviewed_at=reviewed_at,
            verification_outcome=verification_outcome,
            execution_metadata=execution_metadata,
            execution_status=execution_status.value,
            verification_status=verification_status.value,
            created_at=created_at,
        )
        event.record_hash = compute_audit_record_hash(event)
        session.add(event)
        try:
            if commit:
                await session.commit()
                await session.refresh(event)
            else:
                await session.flush()
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
        event_type: AuditEventType | None = None,
        approval_id: UUID | None = None,
        order: Literal["asc", "desc"] = "desc",
    ) -> tuple[list[AuditEvent], int]:
        """List audit events with pagination, filtering, and chronological ordering."""
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
        if event_type is not None:
            filters.append(AuditEvent.event_type == event_type.value)
        if approval_id is not None:
            filters.append(AuditEvent.approval_id == approval_id)

        count_stmt = select(func.count()).select_from(AuditEvent).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        order_col = AuditEvent.created_at.asc() if order == "asc" else AuditEvent.created_at.desc()
        stmt = (
            select(AuditEvent)
            .where(*filters)
            .order_by(order_col, AuditEvent.id.asc())
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

    async def verify_integrity(
        self,
        session: AsyncSession,
        *,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Verify record_hash integrity across recent append-only audit records."""
        stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
        events = list((await session.execute(stmt)).scalars().all())
        verified = 0
        legacy_unhashed = 0
        tampered_ids: list[UUID] = []
        for ev in events:
            if not ev.record_hash:
                legacy_unhashed += 1
                continue
            expected_hash = compute_audit_record_hash(ev)
            if ev.record_hash == expected_hash:
                verified += 1
            else:
                tampered_ids.append(ev.id)
        return {
            "checked": len(events),
            "verified": verified,
            "legacy_unhashed": legacy_unhashed,
            "tampered": len(tampered_ids),
            "tampered_ids": tampered_ids,
            "intact": len(tampered_ids) == 0,
        }

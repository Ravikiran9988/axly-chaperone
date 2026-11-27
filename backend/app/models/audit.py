"""AuditEvent ORM model for append-only gateway decision, approval, and execution recording."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, CheckConstraint, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.enums import AuditEventType, ExecutionStatus
from app.models.types import UTCDateTime, utc_now


class AuditEvent(Base):
    """Immutable audit trail entry created for gateway, approval, execution, and verification."""

    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('allow', 'deny', 'require_approval')",
            name="valid_audit_decision",
        ),
        CheckConstraint(
            "execution_status IN ("
            "'not_executed', 'blocked', 'pending_approval', "
            "'started', 'executed', 'failed', 'rejected', 'expired'"
            ")",
            name="valid_audit_execution_status",
        ),
        CheckConstraint(
            "verification_status IN ("
            "'verified', 'unauthenticated', 'invalid_credentials', "
            "'agent_disabled', 'tool_unavailable', 'validation_failed', "
            "'failed', 'inconclusive', 'not_applicable', "
            "'approved', 'rejected', 'expired'"
            ")",
            name="valid_audit_verification_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=AuditEventType.POLICY_EVALUATION.value,
        server_default="policy_evaluation",
        index=True,
    )
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(1024), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("policies.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=True,
    )
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("approval_requests.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reviewer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    verification_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    execution_metadata: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=True,
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ExecutionStatus.NOT_EXECUTED.value,
    )
    verification_status: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utc_now,
        server_default=func.now(),
        index=True,
    )

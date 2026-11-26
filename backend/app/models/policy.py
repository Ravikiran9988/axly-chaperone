"""Policy ORM model representing deterministic authorization rules."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.types import UTCDateTime, utc_now


class Policy(Base):
    """Authorization policy evaluated deterministically by the Chaperone policy engine."""

    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('allow', 'deny', 'require_approval')",
            name="valid_policy_decision",
        ),
        CheckConstraint("priority >= 0 AND priority <= 10000", name="valid_policy_priority"),
        CheckConstraint("version >= 1", name="valid_policy_version"),
        Index("ix_policies_eval_lookup", "tool_name", "enabled", "priority"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tools.name", ondelete="RESTRICT", onupdate="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_scope: Mapped[str] = mapped_column(String(512), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )

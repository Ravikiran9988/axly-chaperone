"""Agent ORM model representing registered AI agent identities."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.enums import AgentStatus
from app.models.types import UTCDateTime, utc_now


class Agent(Base):
    """Registered AI agent authenticated by a hashed API key."""

    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint("status IN ('active', 'disabled')", name="valid_agent_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AgentStatus.ACTIVE.value,
        index=True,
    )
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

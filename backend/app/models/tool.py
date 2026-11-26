"""Tool ORM model representing registered tool definitions."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.enums import RiskLevel
from app.models.types import UTCDateTime, utc_now


class Tool(Base):
    """Tool definition registered in Chaperone (definition-only in Phase 1)."""

    __tablename__ = "tools"
    __table_args__ = (
        CheckConstraint(
            "risk_level IN ('low', 'medium', 'high', 'critical')",
            name="valid_tool_risk_level",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_level: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=RiskLevel.MEDIUM.value,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
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

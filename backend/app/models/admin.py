"""Administrative user and server-managed session ORM models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.enums import AdminRole, AdminStatus
from app.models.types import UTCDateTime, utc_now


class AdminUser(Base):
    """Individually authenticated administrator principal with explicit RBAC role."""

    __tablename__ = "admin_users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('super_admin', 'approver', 'viewer')",
            name="valid_admin_user_role",
        ),
        CheckConstraint(
            "status IN ('active', 'disabled')",
            name="valid_admin_user_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AdminRole.VIEWER.value,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AdminStatus.ACTIVE.value,
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


class AdminSession(Base):
    """Server-managed short-lived session backing HttpOnly authentication cookies and CSRF."""

    __tablename__ = "admin_sessions"
    __table_args__ = (Index("ix_admin_sessions_expires_revoked", "expires_at", "revoked_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    admin_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("admin_users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_scheme: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="session_cookie",
    )
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime,
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )

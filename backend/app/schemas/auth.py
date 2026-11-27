"""Pydantic v2 schemas for server-managed administrator authentication and RBAC users."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import AdminRole, AdminStatus

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


class AdminLoginRequest(BaseModel):
    """Credentials for exchanging username/password (or bootstrap dev key) for a cookie session."""

    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, max_length=64)
    password: str | None = Field(default=None, max_length=256)
    admin_key: str | None = Field(default=None, max_length=512)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not _USERNAME_RE.fullmatch(cleaned):
            raise ValueError("Username must be 2-64 characters of [A-Za-z0-9._-].")
        return cleaned

    @model_validator(mode="after")
    def validate_auth_mode(self) -> AdminLoginRequest:
        has_user = bool(self.username and self.password)
        has_key = bool(self.admin_key and self.admin_key.strip())
        if not has_user and not has_key:
            raise ValueError("Provide either username/password or bootstrap admin_key.")
        if has_user and has_key:
            raise ValueError("Provide either username/password or admin_key, not both.")
        return self


class AdminSessionResponse(BaseModel):
    """Safe session metadata exposed to the governance UI (never exposes cookie secret)."""

    model_config = ConfigDict(frozen=True)

    authenticated: bool = True
    auth_scheme: str
    reviewer_id: str
    role: AdminRole
    csrf_token: str | None = None
    expires_at: datetime | None = None


class AdminUserCreateRequest(BaseModel):
    """Create an individual administrator principal with explicit role."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: AdminRole = AdminRole.APPROVER

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not _USERNAME_RE.fullmatch(cleaned):
            raise ValueError("Username must be 2-64 characters of [A-Za-z0-9._-].")
        return cleaned


class AdminUserStatusUpdateRequest(BaseModel):
    """Enable, disable, or change role of an existing admin account."""

    model_config = ConfigDict(extra="forbid")

    status: AdminStatus | None = None
    role: AdminRole | None = None


class AdminUserResponse(BaseModel):
    """Public metadata for an admin account (never returns password_hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    role: AdminRole
    status: AdminStatus
    created_at: datetime
    updated_at: datetime


class AdminLogoutResponse(BaseModel):
    """Confirmation of server-side session revocation."""

    model_config = ConfigDict(frozen=True)

    logged_out: Literal[True] = True

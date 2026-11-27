"""Pydantic v2 schemas for human approval requests and decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import ApprovalStatus


class ApprovalDecisionRequest(BaseModel):
    """Administrator approve/reject payload."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=1000)
    execute_now: bool = Field(
        default=True,
        description=(
            "When approving, immediately execute and verify once (set false for 2-step execution)."
        ),
    )

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class ApprovalRejectRequest(BaseModel):
    """Administrator rejection payload."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(default=None, max_length=1000)

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class ApprovalResponse(BaseModel):
    """Public representation of an approval workflow record."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    correlation_id: str
    agent_id: UUID
    tool_name: str
    action: str
    resource: str
    sanitized_arguments: dict[str, Any]
    status: ApprovalStatus
    requested_at: datetime
    expires_at: datetime
    reviewed_at: datetime | None
    reviewer_id: str | None
    reviewer_comment: str | None
    execution_result_reference: dict[str, Any] | None


class ApprovalActionResponse(BaseModel):
    """Response returned after administrator approval or rejection."""

    approval: ApprovalResponse
    execution_status: str | None = None
    output: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None

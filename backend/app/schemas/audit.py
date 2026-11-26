"""Read-only Pydantic v2 schemas for immutable audit trail events."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.enums import ExecutionStatus, PolicyDecision, VerificationStatus


class AuditEventResponse(BaseModel):
    """Append-only audit event record returned by read-only audit endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    correlation_id: str
    agent_id: UUID | None
    tool_name: str
    action: str
    resource: str
    decision: PolicyDecision
    reason: str
    policy_id: UUID | None
    policy_version: int | None
    policy_metadata: dict[str, Any] | None
    execution_status: ExecutionStatus
    verification_status: VerificationStatus
    created_at: datetime

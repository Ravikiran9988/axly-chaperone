"""Read-only Pydantic v2 schemas for append-only chained audit trail events."""

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
    event_type: str
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
    approval_id: UUID | None
    reviewer_id: str | None
    reviewed_at: datetime | None
    verification_outcome: str | None
    execution_metadata: dict[str, Any] | None
    execution_status: ExecutionStatus
    verification_status: VerificationStatus
    chain_seq: int | None = None
    previous_hash: str | None = None
    record_hash: str | None = None
    created_at: datetime


class AuditIntegrityResponse(BaseModel):
    """Full-chain cryptographic digest verification summary across audit_events records."""

    model_config = ConfigDict(frozen=True)

    checked: int
    verified: int
    chain_verified: int = 0
    legacy_unhashed: int
    legacy_pre_chain: int = 0
    tampered: int
    tampered_ids: list[UUID]
    broken_links: list[str] = []
    sequence_gaps: list[dict[str, int | str]] = []
    reordered_ids: list[UUID] = []
    head_seq: int | None = None
    head_hash: str | None = None
    chain_complete: bool = True
    intact: bool

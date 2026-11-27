"""Domain enumerations shared across ORM models, schemas, policy engine, and execution."""

from __future__ import annotations

from enum import StrEnum


class AgentStatus(StrEnum):
    """Lifecycle status for registered AI agents."""

    ACTIVE = "active"
    DISABLED = "disabled"


class RiskLevel(StrEnum):
    """Risk classification assigned to registered tools."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(StrEnum):
    """Deterministic authorization decision returned by the policy engine."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ExecutionStatus(StrEnum):
    """Execution outcome recorded on gateway audit events and responses."""

    NOT_EXECUTED = "not_executed"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"
    STARTED = "started"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class VerificationStatus(StrEnum):
    """Outcome of identity, tool, resource, and governance verification checks."""

    VERIFIED = "verified"
    UNAUTHENTICATED = "unauthenticated"
    INVALID_CREDENTIALS = "invalid_credentials"
    AGENT_DISABLED = "agent_disabled"
    TOOL_UNAVAILABLE = "tool_unavailable"
    VALIDATION_FAILED = "validation_failed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalStatus(StrEnum):
    """Lifecycle states for human-in-the-loop approval requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"


class VerificationOutcome(StrEnum):
    """Independent post-execution state verification statuses."""

    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class AuditEventType(StrEnum):
    """Structured event types recorded in the append-only audit trail."""

    GATEWAY_EVALUATE = "gateway_evaluate"
    GATEWAY_EXECUTE = "gateway_execute"
    AUTHENTICATION = "authentication"
    POLICY_EVALUATION = "policy_evaluation"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_APPROVED = "approval_approved"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    EXECUTION_STARTED = "execution_started"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    VERIFICATION_COMPLETED = "verification_completed"

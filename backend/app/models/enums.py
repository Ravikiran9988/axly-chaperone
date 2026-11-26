"""Domain enumerations shared across ORM models, schemas, and policy engine."""

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
    """Execution outcome recorded on gateway audit events (Phase 1 never executes)."""

    NOT_EXECUTED = "not_executed"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"


class VerificationStatus(StrEnum):
    """Outcome of identity, tool, and resource verification checks."""

    VERIFIED = "verified"
    UNAUTHENTICATED = "unauthenticated"
    INVALID_CREDENTIALS = "invalid_credentials"
    AGENT_DISABLED = "agent_disabled"
    TOOL_UNAVAILABLE = "tool_unavailable"
    VALIDATION_FAILED = "validation_failed"

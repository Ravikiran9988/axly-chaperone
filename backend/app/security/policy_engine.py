"""Deterministic Python policy evaluation engine (no LLM or external side effects).

Precedence & Conflict Resolution Rules:
1. Unauthenticated or missing agents are always DENIED.
2. Disabled agents are always DENIED.
3. Unknown or disabled tools are always DENIED.
4. Invalid, traversal-bearing, or argument-mismatched resources are always DENIED.
5. Only enabled policies matching `(agent_id or global, tool_name, action or '*', scope)` apply.
6. Default DENY when zero enabled policies match.
7. Explicit DENY hard-block: if ANY matching policy has decision=DENY, the final decision is DENY
   (explicit denials cannot be bypassed by ALLOW or REQUIRE_APPROVAL at any priority). Among
   matching DENY policies, the highest priority (then highest specificity, then lowest policy ID)
   is selected as matched_policy_id.
8. Among non-DENY matching policies (ALLOW vs REQUIRE_APPROVAL), the highest numeric priority tier
   wins. On a priority tie, REQUIRE_APPROVAL overrides ALLOW (fail-safe human control). Further ties
   break by specificity (agent-specific > global, exact action > '*', exact scope > prefix > '*')
   and finally lexicographical UUID order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.models.enums import AgentStatus, PolicyDecision, VerificationStatus
from app.security.resource_validator import (
    ResourceValidationError,
    resource_matches_scope,
    validate_and_normalize_resource,
)


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Identity and status snapshot of the requesting agent."""

    id: UUID | None
    status: AgentStatus | None
    authenticated: bool


@dataclass(frozen=True, slots=True)
class ToolContext:
    """Registry snapshot of the requested tool."""

    name: str
    category: str | None
    exists: bool
    enabled: bool


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """Immutable policy rule candidate evaluated by the policy engine."""

    id: UUID
    name: str
    agent_id: UUID | None
    tool_name: str
    action: str
    resource_scope: str
    decision: PolicyDecision
    enabled: bool
    priority: int
    version: int


@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    """Normalized inputs for a single tool authorization evaluation."""

    tool_name: str
    action: str
    resource: str
    arguments: dict[str, Any] | None
    correlation_id: str


@dataclass(frozen=True, slots=True)
class PolicyEvaluationResult:
    """Deterministic evaluation output consumed by GatewayService and AuditService."""

    decision: PolicyDecision
    reason: str
    matched_policy_id: UUID | None
    matched_policy_name: str | None
    matched_policy_version: int | None
    matched_policy_priority: int | None
    agent_id: UUID | None
    tool_name: str
    action: str
    resource: str
    correlation_id: str
    verification_status: VerificationStatus


def _scope_specificity(scope: str) -> int:
    if scope == "*":
        return 0
    if scope.endswith("/*") or scope.startswith("*@"):
        return 1
    return 2


def _policy_specificity(policy: PolicyRule) -> tuple[int, int, int]:
    agent_spec = 1 if policy.agent_id is not None else 0
    action_spec = 1 if policy.action != "*" else 0
    scope_spec = _scope_specificity(policy.resource_scope)
    return (agent_spec, action_spec, scope_spec)


def _policy_matches(
    policy: PolicyRule,
    *,
    agent_id: UUID,
    tool_name: str,
    action: str,
    normalized_resource: str,
) -> bool:
    if not policy.enabled:
        return False
    if policy.agent_id is not None and policy.agent_id != agent_id:
        return False
    if policy.tool_name != tool_name:
        return False
    if policy.action != "*" and policy.action != action:
        return False
    return resource_matches_scope(policy.resource_scope, normalized_resource)


class PolicyEngine:
    """Deterministic least-privilege authorization engine."""

    def evaluate(
        self,
        *,
        agent: AgentContext,
        tool: ToolContext,
        request: EvaluationRequest,
        policies: list[PolicyRule] | tuple[PolicyRule, ...],
    ) -> PolicyEvaluationResult:
        """Evaluate an agent tool request deterministically against tools and policies."""
        action = request.action.strip().lower()
        safe_raw_resource = request.resource[:1024] if isinstance(request.resource, str) else ""

        if not agent.authenticated or agent.id is None:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason="Agent authentication failed or missing",
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=action,
                resource=safe_raw_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.UNAUTHENTICATED,
            )

        if agent.status != AgentStatus.ACTIVE:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason="Agent is disabled",
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=action,
                resource=safe_raw_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.AGENT_DISABLED,
            )

        if not tool.exists:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason=f"Tool '{request.tool_name}' is not registered",
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=action,
                resource=safe_raw_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.TOOL_UNAVAILABLE,
            )

        if not tool.enabled:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason=f"Tool '{request.tool_name}' is disabled",
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=request.tool_name,
                action=action,
                resource=safe_raw_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.TOOL_UNAVAILABLE,
            )

        try:
            normalized_resource = validate_and_normalize_resource(
                tool_category=tool.category,
                tool_name=tool.name,
                resource=request.resource,
                arguments=request.arguments,
            )
        except ResourceValidationError as exc:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason=str(exc),
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=tool.name,
                action=action,
                resource=safe_raw_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.VALIDATION_FAILED,
            )

        matching = [
            policy
            for policy in policies
            if _policy_matches(
                policy,
                agent_id=agent.id,
                tool_name=tool.name,
                action=action,
                normalized_resource=normalized_resource,
            )
        ]

        if not matching:
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason="No matching permission policy",
                matched_policy_id=None,
                matched_policy_name=None,
                matched_policy_version=None,
                matched_policy_priority=None,
                agent_id=agent.id,
                tool_name=tool.name,
                action=action,
                resource=normalized_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.VERIFIED,
            )

        explicit_denies = [p for p in matching if p.decision == PolicyDecision.DENY]
        if explicit_denies:
            winner = min(
                explicit_denies,
                key=lambda p: (
                    -p.priority,
                    -_policy_specificity(p)[0],
                    -_policy_specificity(p)[1],
                    -_policy_specificity(p)[2],
                    str(p.id),
                ),
            )
            return PolicyEvaluationResult(
                decision=PolicyDecision.DENY,
                reason=f"Denied by explicit policy '{winner.name}' (priority {winner.priority})",
                matched_policy_id=winner.id,
                matched_policy_name=winner.name,
                matched_policy_version=winner.version,
                matched_policy_priority=winner.priority,
                agent_id=agent.id,
                tool_name=tool.name,
                action=action,
                resource=normalized_resource,
                correlation_id=request.correlation_id,
                verification_status=VerificationStatus.VERIFIED,
            )

        winner = min(
            matching,
            key=lambda p: (
                -p.priority,
                0 if p.decision == PolicyDecision.REQUIRE_APPROVAL else 1,
                -_policy_specificity(p)[0],
                -_policy_specificity(p)[1],
                -_policy_specificity(p)[2],
                str(p.id),
            ),
        )
        if winner.decision == PolicyDecision.REQUIRE_APPROVAL:
            reason = (
                f"Human approval required by policy '{winner.name}' (priority {winner.priority})"
            )
        else:
            reason = f"Allowed by policy '{winner.name}' (priority {winner.priority})"

        return PolicyEvaluationResult(
            decision=winner.decision,
            reason=reason,
            matched_policy_id=winner.id,
            matched_policy_name=winner.name,
            matched_policy_version=winner.version,
            matched_policy_priority=winner.priority,
            agent_id=agent.id,
            tool_name=tool.name,
            action=action,
            resource=normalized_resource,
            correlation_id=request.correlation_id,
            verification_status=VerificationStatus.VERIFIED,
        )

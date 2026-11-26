"""Gateway evaluation orchestration service (Phase 1: evaluate & audit only, never execute)."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.enums import AgentStatus, ExecutionStatus, PolicyDecision
from app.models.policy import Policy
from app.models.tool import Tool
from app.schemas.gateway import GatewayEvaluateRequest, GatewayEvaluateResponse
from app.security.authentication import AgentAuthResult
from app.security.authorization import enforce_agent_access
from app.security.policy_engine import (
    AgentContext,
    EvaluationRequest,
    PolicyEngine,
    PolicyRule,
    ToolContext,
)
from app.services.audit_service import AuditService

logger = logging.getLogger("chaperone.gateway")


class GatewayService:
    """Coordinates authentication verification, policy evaluation, and fail-closed audit logging."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_service = audit_service or AuditService()

    async def record_unauthenticated_attempt(
        self,
        session: AsyncSession,
        *,
        auth_result: AgentAuthResult,
        correlation_id: str,
        tool_name: str = "gateway",
        action: str = "evaluate",
        resource: str = "api/v1/gateway/evaluate",
    ) -> None:
        """Persist an audit event for unauthenticated or disabled-agent calls, then raise."""
        await self._audit_service.record_event(
            session,
            correlation_id=correlation_id,
            agent_id=auth_result.agent.id if auth_result.agent is not None else None,
            tool_name=tool_name,
            action=action,
            resource=resource,
            decision=PolicyDecision.DENY,
            reason=auth_result.failure_reason or "Agent authentication failed.",
            policy_id=None,
            policy_version=None,
            policy_metadata={"phase": "phase1_evaluate_only", "stage": "authentication"},
            execution_status=ExecutionStatus.NOT_EXECUTED,
            verification_status=auth_result.verification_status,
        )
        enforce_agent_access(auth_result)

    async def evaluate_request(
        self,
        session: AsyncSession,
        *,
        agent: Agent,
        payload: GatewayEvaluateRequest,
        correlation_id: str,
    ) -> GatewayEvaluateResponse:
        """Evaluate an authenticated agent's tool request and persist an immutable audit event."""
        tool_stmt = select(Tool).where(Tool.name == payload.tool_name)
        tool_row = (await session.execute(tool_stmt)).scalar_one_or_none()

        tool_ctx = ToolContext(
            name=tool_row.name if tool_row is not None else payload.tool_name,
            category=tool_row.category if tool_row is not None else None,
            exists=tool_row is not None,
            enabled=tool_row.enabled if tool_row is not None else False,
        )

        policy_rules: list[PolicyRule] = []
        if tool_ctx.exists and tool_ctx.enabled:
            policy_stmt = select(Policy).where(
                Policy.tool_name == tool_ctx.name,
                Policy.enabled.is_(True),
                or_(Policy.agent_id.is_(None), Policy.agent_id == agent.id),
            )
            policy_rows = (await session.execute(policy_stmt)).scalars().all()
            policy_rules = [
                PolicyRule(
                    id=row.id,
                    name=row.name,
                    agent_id=row.agent_id,
                    tool_name=row.tool_name,
                    action=row.action,
                    resource_scope=row.resource_scope,
                    decision=PolicyDecision(row.decision),
                    enabled=row.enabled,
                    priority=row.priority,
                    version=row.version,
                )
                for row in policy_rows
            ]

        agent_ctx = AgentContext(
            id=agent.id,
            status=AgentStatus(agent.status),
            authenticated=True,
        )
        eval_request = EvaluationRequest(
            tool_name=payload.tool_name,
            action=payload.action,
            resource=payload.resource,
            arguments=payload.arguments,
            correlation_id=correlation_id,
        )

        result = self._policy_engine.evaluate(
            agent=agent_ctx,
            tool=tool_ctx,
            request=eval_request,
            policies=policy_rules,
        )

        policy_metadata: dict[str, Any] = {
            "phase": "phase1_evaluate_only",
            "tool_exists": tool_ctx.exists,
            "tool_enabled": tool_ctx.enabled,
        }
        if result.matched_policy_id is not None:
            policy_metadata.update(
                {
                    "policy_name": result.matched_policy_name,
                    "policy_priority": result.matched_policy_priority,
                }
            )

        await self._audit_service.record_event(
            session,
            correlation_id=result.correlation_id,
            agent_id=result.agent_id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            decision=result.decision,
            reason=result.reason,
            policy_id=result.matched_policy_id,
            policy_version=result.matched_policy_version,
            policy_metadata=policy_metadata,
            execution_status=ExecutionStatus.NOT_EXECUTED,
            verification_status=result.verification_status,
        )

        logger.info(
            "Gateway evaluated tool request",
            extra={
                "correlation_id": result.correlation_id,
                "agent_id": str(result.agent_id),
                "decision": result.decision.value.upper(),
            },
        )

        decision_label = result.decision.value.upper()
        return GatewayEvaluateResponse(
            correlation_id=result.correlation_id,
            decision=decision_label,  # type: ignore[arg-type]
            reason=result.reason,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            agent_id=agent.id,
            matched_policy_id=result.matched_policy_id,
            execution_status=ExecutionStatus.NOT_EXECUTED.value,
        )

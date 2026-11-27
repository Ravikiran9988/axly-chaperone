"""Gateway orchestration service for policy evaluation and controlled Phase 2 execution."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.approvals.service import ApprovalService, compute_payload_hash, sanitize_arguments
from app.core.config import Settings
from app.core.exceptions import AuthorizationError, BadRequestError, ConflictError
from app.execution.dispatcher import ExecutionDispatcher
from app.models.agent import Agent
from app.models.enums import (
    AgentStatus,
    AuditEventType,
    ExecutionStatus,
    PolicyDecision,
    VerificationOutcome,
    VerificationStatus,
)
from app.models.mock_state import ExecutionIdempotency
from app.models.policy import Policy
from app.models.tool import Tool
from app.schemas.gateway import (
    GatewayEvaluateRequest,
    GatewayEvaluateResponse,
    GatewayExecuteRequest,
    GatewayExecuteResponse,
    VerificationSummary,
)
from app.security.authentication import AgentAuthResult
from app.security.authorization import enforce_agent_access
from app.security.policy_engine import (
    AgentContext,
    EvaluationRequest,
    PolicyEngine,
    PolicyEvaluationResult,
    PolicyRule,
    ToolContext,
)
from app.services.audit_service import AuditService
from app.verification.engine import VerificationEngine

logger = logging.getLogger("chaperone.gateway")


def _compute_execute_request_hash(
    agent_id: Any,
    payload: GatewayExecuteRequest,
) -> str:
    canonical = json.dumps(
        {
            "agent_id": str(agent_id),
            "tool_name": payload.tool_name,
            "action": payload.action,
            "resource": payload.resource,
            "arguments": payload.arguments,
            "approval_id": str(payload.approval_id) if payload.approval_id else None,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class GatewayService:
    """Coordinates auth verification, deterministic policy evaluation, execution, and audit."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        audit_service: AuditService | None = None,
        dispatcher: ExecutionDispatcher | None = None,
        verification_engine: VerificationEngine | None = None,
        approval_service: ApprovalService | None = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._audit_service = audit_service or AuditService()
        self._dispatcher = dispatcher or ExecutionDispatcher()
        self._verifier = verification_engine or VerificationEngine()
        self._approvals = approval_service or ApprovalService(
            audit_service=self._audit_service,
            policy_engine=self._policy_engine,
            dispatcher=self._dispatcher,
            verification_engine=self._verifier,
        )

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
        agent_id = auth_result.agent.id if auth_result.agent is not None else None
        await session.commit()
        await self._audit_service.record_event(
            session,
            correlation_id=correlation_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            decision=PolicyDecision.DENY,
            reason=auth_result.failure_reason or "Agent authentication failed.",
            policy_id=None,
            policy_version=None,
            policy_metadata={"stage": "authentication"},
            execution_status=ExecutionStatus.NOT_EXECUTED,
            verification_status=auth_result.verification_status,
            event_type=AuditEventType.AUTHENTICATION,
        )
        enforce_agent_access(auth_result)

    async def _evaluate_policy(
        self,
        session: AsyncSession,
        *,
        agent: Agent,
        payload: GatewayEvaluateRequest,
        correlation_id: str,
    ) -> tuple[PolicyEvaluationResult, ToolContext]:
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

        result = self._policy_engine.evaluate(
            agent=AgentContext(
                id=agent.id,
                status=AgentStatus(agent.status),
                authenticated=True,
            ),
            tool=tool_ctx,
            request=EvaluationRequest(
                tool_name=payload.tool_name,
                action=payload.action,
                resource=payload.resource,
                arguments=payload.arguments,
                correlation_id=correlation_id,
            ),
            policies=policy_rules,
        )
        # Close read-only snapshot cleanly before downstream audit lock acquisition
        await session.commit()
        return result, tool_ctx

    async def evaluate_request(
        self,
        session: AsyncSession,
        *,
        agent: Agent,
        payload: GatewayEvaluateRequest,
        correlation_id: str,
    ) -> GatewayEvaluateResponse:
        """Evaluate an authenticated agent's tool request without executing the tool."""
        result, tool_ctx = await self._evaluate_policy(
            session, agent=agent, payload=payload, correlation_id=correlation_id
        )

        policy_metadata: dict[str, Any] = {
            "phase": "evaluate_only",
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
            event_type=AuditEventType.GATEWAY_EVALUATE,
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

    async def execute_request(
        self,
        session: AsyncSession,
        *,
        agent: Agent,
        payload: GatewayExecuteRequest,
        correlation_id: str,
        settings: Settings,
        idempotency_key: str | None = None,
    ) -> tuple[int, GatewayExecuteResponse]:
        """Evaluate, enforce approvals, dispatch controlled execution, verify, and audit."""
        encoded_args = json.dumps(payload.arguments, default=str).encode("utf-8")
        if len(encoded_args) > settings.max_argument_payload_bytes:
            max_bytes = settings.max_argument_payload_bytes
            raise BadRequestError(
                f"Tool arguments exceed maximum size of {max_bytes} bytes.",
                code="ARGUMENT_PAYLOAD_TOO_LARGE",
            )

        request_hash = _compute_execute_request_hash(agent.id, payload)
        if idempotency_key is not None:
            existing_idem = (
                await session.execute(
                    select(ExecutionIdempotency).where(
                        ExecutionIdempotency.agent_id == agent.id,
                        ExecutionIdempotency.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing_idem is not None:
                if existing_idem.request_hash != request_hash:
                    raise ConflictError(
                        "Idempotency-Key reused with a different request payload.",
                        code="IDEMPOTENCY_KEY_CONFLICT",
                    )
                return (
                    existing_idem.response_status_code,
                    GatewayExecuteResponse.model_validate(existing_idem.response_body),
                )

        # Two-step approved execution flow when approval_id is supplied
        if payload.approval_id is not None:
            approval = await self._approvals.get_approval(session, payload.approval_id)
            if approval.agent_id != agent.id:
                raise AuthorizationError(
                    "Approval request does not belong to the authenticated agent.",
                    code="APPROVAL_AGENT_MISMATCH",
                )
            eval_result, _ = await self._evaluate_policy(
                session, agent=agent, payload=payload, correlation_id=correlation_id
            )
            if eval_result.decision == PolicyDecision.DENY:
                await self._audit_service.record_event(
                    session,
                    correlation_id=correlation_id,
                    agent_id=agent.id,
                    tool_name=payload.tool_name,
                    action=payload.action,
                    resource=eval_result.resource,
                    decision=PolicyDecision.DENY,
                    reason=eval_result.reason,
                    policy_id=eval_result.matched_policy_id,
                    policy_version=eval_result.matched_policy_version,
                    policy_metadata={"stage": "approved_execute_policy_check"},
                    approval_id=approval.id,
                    execution_status=ExecutionStatus.BLOCKED,
                    verification_status=eval_result.verification_status,
                    event_type=AuditEventType.GATEWAY_EXECUTE,
                )
                return (
                    403,
                    GatewayExecuteResponse(
                        correlation_id=correlation_id,
                        decision="DENY",
                        status="BLOCKED",
                        message=eval_result.reason,
                        tool_name=payload.tool_name,
                        action=payload.action,
                        resource=eval_result.resource,
                        agent_id=agent.id,
                        approval_id=approval.id,
                        matched_policy_id=eval_result.matched_policy_id,
                    ),
                )

            presented_hash = compute_payload_hash(
                agent_id=agent.id,
                tool_name=payload.tool_name,
                action=payload.action,
                resource=eval_result.resource,
                sanitized_arguments=sanitize_arguments(payload.arguments),
            )
            if presented_hash != approval.payload_hash:
                await self._audit_service.record_event(
                    session,
                    correlation_id=correlation_id,
                    agent_id=agent.id,
                    tool_name=payload.tool_name,
                    action=payload.action,
                    resource=eval_result.resource,
                    decision=PolicyDecision.DENY,
                    reason="Payload tampering detected: request does not match approved payload.",
                    policy_id=approval.policy_id,
                    policy_version=approval.policy_version,
                    policy_metadata={"stage": "approval_payload_binding"},
                    approval_id=approval.id,
                    execution_status=ExecutionStatus.BLOCKED,
                    verification_status=VerificationStatus.VALIDATION_FAILED,
                    event_type=AuditEventType.GATEWAY_EXECUTE,
                )
                raise AuthorizationError(
                    "Request payload does not match the approved action.",
                    code="PAYLOAD_TAMPERING_DETECTED",
                )

            updated_approval, verification, output = await self._approvals.execute_approved_request(
                session,
                approval_id=approval.id,
                settings=settings,
                correlation_id=correlation_id,
            )
            exec_ok = updated_approval.status == "executed"
            response = GatewayExecuteResponse(
                correlation_id=correlation_id,
                decision="ALLOW",
                status="EXECUTED" if exec_ok else "FAILED",
                message="Approved tool execution completed."
                if exec_ok
                else "Approved tool execution failed.",
                tool_name=updated_approval.tool_name,
                action=updated_approval.action,
                resource=updated_approval.resource,
                agent_id=agent.id,
                approval_id=updated_approval.id,
                matched_policy_id=updated_approval.policy_id,
                output=output,
                verification=VerificationSummary(
                    verification_id=verification.verification_id,
                    status=verification.status.value.upper(),  # type: ignore[arg-type]
                    method=verification.method,
                    message=verification.message,
                ),
            )
            await self._persist_idempotency(
                session,
                agent_id=agent.id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                status_code=200,
                response=response,
            )
            return 200, response

        # Standard single-step execution path
        result, tool_ctx = await self._evaluate_policy(
            session, agent=agent, payload=payload, correlation_id=correlation_id
        )
        policy_metadata: dict[str, Any] = {
            "phase": "phase2_execute",
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

        if result.decision == PolicyDecision.DENY:
            await self._audit_service.record_event(
                session,
                correlation_id=result.correlation_id,
                agent_id=agent.id,
                tool_name=result.tool_name,
                action=result.action,
                resource=result.resource,
                decision=PolicyDecision.DENY,
                reason=result.reason,
                policy_id=result.matched_policy_id,
                policy_version=result.matched_policy_version,
                policy_metadata=policy_metadata,
                execution_status=ExecutionStatus.BLOCKED,
                verification_status=result.verification_status,
                event_type=AuditEventType.POLICY_EVALUATION,
            )
            return (
                403,
                GatewayExecuteResponse(
                    correlation_id=result.correlation_id,
                    decision="DENY",
                    status="BLOCKED",
                    message=result.reason,
                    tool_name=result.tool_name,
                    action=result.action,
                    resource=result.resource,
                    agent_id=agent.id,
                    matched_policy_id=result.matched_policy_id,
                ),
            )

        if result.decision == PolicyDecision.REQUIRE_APPROVAL:
            # Record policy evaluation first, then create pending approval
            await self._audit_service.record_event(
                session,
                correlation_id=result.correlation_id,
                agent_id=agent.id,
                tool_name=result.tool_name,
                action=result.action,
                resource=result.resource,
                decision=PolicyDecision.REQUIRE_APPROVAL,
                reason=result.reason,
                policy_id=result.matched_policy_id,
                policy_version=result.matched_policy_version,
                policy_metadata=policy_metadata,
                execution_status=ExecutionStatus.PENDING_APPROVAL,
                verification_status=result.verification_status,
                event_type=AuditEventType.POLICY_EVALUATION,
            )
            approval = await self._approvals.create_pending_approval(
                session,
                decision=result.decision,
                correlation_id=result.correlation_id,
                agent_id=agent.id,
                tool_name=result.tool_name,
                action=result.action,
                resource=result.resource,
                arguments=payload.arguments,
                policy_id=result.matched_policy_id,
                policy_version=result.matched_policy_version,
                settings=settings,
                idempotency_key=idempotency_key,
            )
            response = GatewayExecuteResponse(
                correlation_id=result.correlation_id,
                decision="REQUIRE_APPROVAL",
                status="PENDING",
                message="Administrator approval required",
                tool_name=result.tool_name,
                action=result.action,
                resource=result.resource,
                agent_id=agent.id,
                approval_id=approval.id,
                matched_policy_id=result.matched_policy_id,
            )
            await self._persist_idempotency(
                session,
                agent_id=agent.id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                status_code=202,
                response=response,
            )
            return 202, response

        # Decision is ALLOW: fail-closed audit BEFORE invoking any adapter
        await self._audit_service.record_event(
            session,
            correlation_id=result.correlation_id,
            agent_id=agent.id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            decision=PolicyDecision.ALLOW,
            reason=result.reason,
            policy_id=result.matched_policy_id,
            policy_version=result.matched_policy_version,
            policy_metadata=policy_metadata,
            execution_status=ExecutionStatus.STARTED,
            verification_status=result.verification_status,
            event_type=AuditEventType.EXECUTION_STARTED,
            commit=True,
        )

        dispatch_res = await self._dispatcher.dispatch(
            session,
            correlation_id=result.correlation_id,
            agent_id=agent.id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            arguments=payload.arguments,
            settings=settings,
        )
        await session.commit()
        exec_ok = dispatch_res.status == ExecutionStatus.EXECUTED

        exec_audit = await self._audit_service.record_event(
            session,
            correlation_id=result.correlation_id,
            agent_id=agent.id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            decision=PolicyDecision.ALLOW,
            reason=dispatch_res.summary,
            policy_id=result.matched_policy_id,
            policy_version=result.matched_policy_version,
            policy_metadata=policy_metadata,
            execution_metadata=dispatch_res.metadata,
            execution_status=dispatch_res.status,
            verification_status=(
                VerificationStatus.VERIFIED if exec_ok else VerificationStatus.FAILED
            ),
            event_type=(
                AuditEventType.EXECUTION_COMPLETED if exec_ok else AuditEventType.EXECUTION_FAILED
            ),
            commit=True,
        )

        verification = await self._verifier.verify_and_record(
            session,
            correlation_id=result.correlation_id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            arguments=payload.arguments,
            execution_succeeded=exec_ok,
            execution_metadata=dispatch_res.metadata,
            execution_output=dispatch_res.output if exec_ok else None,
            settings=settings,
            audit_event_id=exec_audit.id,
        )
        await session.commit()

        await self._audit_service.record_event(
            session,
            correlation_id=result.correlation_id,
            agent_id=agent.id,
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            decision=PolicyDecision.ALLOW,
            reason=verification.message,
            policy_id=result.matched_policy_id,
            policy_version=result.matched_policy_version,
            policy_metadata={"verification_method": verification.method},
            verification_outcome=verification.status.value,
            execution_metadata={"verification_id": str(verification.verification_id)},
            execution_status=dispatch_res.status,
            verification_status=VerificationStatus(verification.status.value),
            event_type=AuditEventType.VERIFICATION_COMPLETED,
            commit=True,
        )

        final_status: Any = "EXECUTED" if exec_ok else "FAILED"
        if exec_ok and verification.status == VerificationOutcome.FAILED:
            final_status = "FAILED"

        response = GatewayExecuteResponse(
            correlation_id=result.correlation_id,
            decision="ALLOW",
            status=final_status,
            message=dispatch_res.summary
            if exec_ok
            else (dispatch_res.error_message or dispatch_res.summary),
            tool_name=result.tool_name,
            action=result.action,
            resource=result.resource,
            agent_id=agent.id,
            matched_policy_id=result.matched_policy_id,
            output=dispatch_res.output if exec_ok else None,
            verification=VerificationSummary(
                verification_id=verification.verification_id,
                status=verification.status.value.upper(),  # type: ignore[arg-type]
                method=verification.method,
                message=verification.message,
            ),
        )
        await self._persist_idempotency(
            session,
            agent_id=agent.id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            status_code=200,
            response=response,
        )
        return 200, response

    async def _persist_idempotency(
        self,
        session: AsyncSession,
        *,
        agent_id: Any,
        idempotency_key: str | None,
        request_hash: str,
        status_code: int,
        response: GatewayExecuteResponse,
    ) -> None:
        if idempotency_key is None:
            return
        record = ExecutionIdempotency(
            agent_id=agent_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            response_status_code=status_code,
            response_body=response.model_dump(mode="json"),
        )
        session.add(record)
        await session.commit()

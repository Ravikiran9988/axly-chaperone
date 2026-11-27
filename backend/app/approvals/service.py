"""Approval lifecycle service with atomic state transitions, binding, and re-evaluation."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.approvals.models import ApprovalRequest
from app.core.config import Settings
from app.core.exceptions import (
    AuthorizationError,
    ConflictError,
    ResourceNotFoundError,
)
from app.core.logging import redact_secrets
from app.execution.dispatcher import ExecutionDispatcher
from app.models.agent import Agent
from app.models.enums import (
    AgentStatus,
    ApprovalStatus,
    AuditEventType,
    ExecutionStatus,
    PolicyDecision,
    VerificationOutcome,
    VerificationStatus,
)
from app.models.policy import Policy
from app.models.tool import Tool
from app.security.policy_engine import (
    AgentContext,
    EvaluationRequest,
    PolicyEngine,
    PolicyRule,
    ToolContext,
)
from app.services.audit_service import AuditService
from app.verification.engine import VerificationEngine, VerificationResult


def sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact accidental credential tokens while preserving payload structure."""

    def _clean(value: Any) -> Any:
        if isinstance(value, str):
            return redact_secrets(value)
        if isinstance(value, dict):
            return {str(k): _clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_clean(item) for item in value]
        return value

    cleaned = _clean(arguments)
    return cleaned if isinstance(cleaned, dict) else {}


def compute_payload_hash(
    *,
    agent_id: UUID,
    tool_name: str,
    action: str,
    resource: str,
    sanitized_arguments: dict[str, Any],
) -> str:
    """Compute a deterministic SHA-256 hash binding approval to the exact execution payload."""
    canonical_doc = json.dumps(
        {
            "agent_id": str(agent_id),
            "tool_name": tool_name,
            "action": action,
            "resource": resource,
            "arguments": sanitized_arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical_doc.encode("utf-8")).hexdigest()


class ApprovalService:
    """Manages human approval requests, atomic claims, and post-approval execution."""

    def __init__(
        self,
        *,
        audit_service: AuditService | None = None,
        policy_engine: PolicyEngine | None = None,
        dispatcher: ExecutionDispatcher | None = None,
        verification_engine: VerificationEngine | None = None,
    ) -> None:
        self._audit = audit_service or AuditService()
        self._policy_engine = policy_engine or PolicyEngine()
        self._dispatcher = dispatcher or ExecutionDispatcher()
        self._verifier = verification_engine or VerificationEngine()

    async def create_pending_approval(
        self,
        session: AsyncSession,
        *,
        decision: PolicyDecision,
        correlation_id: str,
        agent_id: UUID,
        tool_name: str,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        policy_id: UUID | None,
        policy_version: int | None,
        settings: Settings,
        idempotency_key: str | None = None,
    ) -> ApprovalRequest:
        """Create a PENDING approval request strictly from a REQUIRE_APPROVAL decision."""
        if decision != PolicyDecision.REQUIRE_APPROVAL:
            raise AuthorizationError(
                "Only REQUIRE_APPROVAL policy decisions can create approval requests.",
                code="INVALID_APPROVAL_SOURCE",
            )

        sanitized = sanitize_arguments(arguments)
        payload_hash = compute_payload_hash(
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            sanitized_arguments=sanitized,
        )
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=settings.approval_ttl_seconds)

        approval = ApprovalRequest(
            correlation_id=correlation_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            sanitized_arguments=sanitized,
            payload_hash=payload_hash,
            policy_id=policy_id,
            policy_version=policy_version,
            idempotency_key=idempotency_key,
            status=ApprovalStatus.PENDING.value,
            requested_at=now,
            expires_at=expires_at,
        )
        session.add(approval)
        await session.flush()

        await self._audit.record_event(
            session,
            correlation_id=correlation_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            decision=PolicyDecision.REQUIRE_APPROVAL,
            reason="Administrator approval required before tool execution.",
            policy_id=policy_id,
            policy_version=policy_version,
            policy_metadata={
                "phase": "phase2_execute",
                "approval_ttl_seconds": settings.approval_ttl_seconds,
            },
            approval_id=approval.id,
            execution_status=ExecutionStatus.PENDING_APPROVAL,
            verification_status=VerificationStatus.VERIFIED,
            event_type=AuditEventType.APPROVAL_REQUESTED,
            commit=True,
        )
        await session.refresh(approval)
        return approval

    async def list_approvals(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        status_filter: ApprovalStatus | None = None,
        agent_id: UUID | None = None,
        tool_name: str | None = None,
    ) -> tuple[list[ApprovalRequest], int]:
        """List approval requests with pagination and optional status/agent/tool filters."""
        filters = []
        if status_filter is not None:
            filters.append(ApprovalRequest.status == status_filter.value)
        if agent_id is not None:
            filters.append(ApprovalRequest.agent_id == agent_id)
        if tool_name is not None:
            filters.append(ApprovalRequest.tool_name == tool_name.strip().lower())

        count_stmt = select(func.count()).select_from(ApprovalRequest).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        stmt = (
            select(ApprovalRequest)
            .where(*filters)
            .order_by(ApprovalRequest.requested_at.desc(), ApprovalRequest.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_approval(self, session: AsyncSession, approval_id: UUID) -> ApprovalRequest:
        """Retrieve an approval request by UUID or raise ResourceNotFoundError."""
        row = (
            await session.execute(select(ApprovalRequest).where(ApprovalRequest.id == approval_id))
        ).scalar_one_or_none()
        if row is None:
            raise ResourceNotFoundError(f"Approval request '{approval_id}' not found.")
        return row

    async def _expire_if_elapsed(
        self,
        session: AsyncSession,
        approval: ApprovalRequest,
        *,
        reviewer_id: str | None = None,
    ) -> None:
        now = datetime.now(UTC)
        if approval.status == ApprovalStatus.PENDING.value and now >= approval.expires_at:
            stmt = (
                update(ApprovalRequest)
                .where(
                    ApprovalRequest.id == approval.id,
                    ApprovalRequest.status == ApprovalStatus.PENDING.value,
                )
                .values(status=ApprovalStatus.EXPIRED.value)
            )
            res = await session.execute(stmt)
            if res.rowcount and res.rowcount > 0:
                await self._audit.record_event(
                    session,
                    correlation_id=approval.correlation_id,
                    agent_id=approval.agent_id,
                    tool_name=approval.tool_name,
                    action=approval.action,
                    resource=approval.resource,
                    decision=PolicyDecision.DENY,
                    reason="Approval request expired before review.",
                    policy_id=approval.policy_id,
                    policy_version=approval.policy_version,
                    policy_metadata={"stage": "approval_expiration"},
                    approval_id=approval.id,
                    reviewer_id=reviewer_id,
                    reviewed_at=now,
                    execution_status=ExecutionStatus.EXPIRED,
                    verification_status=VerificationStatus.EXPIRED,
                    event_type=AuditEventType.APPROVAL_EXPIRED,
                    commit=True,
                )
            else:
                await session.commit()
            raise ConflictError("Approval request has expired.", code="APPROVAL_EXPIRED")

    async def _reevaluate_before_execution(
        self,
        session: AsyncSession,
        approval: ApprovalRequest,
    ) -> None:
        """Re-evaluate agent, tool, and policy state immediately before execution."""
        agent = (
            await session.execute(select(Agent).where(Agent.id == approval.agent_id))
        ).scalar_one_or_none()
        tool = (
            await session.execute(select(Tool).where(Tool.name == approval.tool_name))
        ).scalar_one_or_none()

        policy_rules: list[PolicyRule] = []
        if tool is not None and tool.enabled:
            policy_rows = (
                (
                    await session.execute(
                        select(Policy).where(
                            Policy.tool_name == tool.name,
                            Policy.enabled.is_(True),
                            or_(Policy.agent_id.is_(None), Policy.agent_id == approval.agent_id),
                        )
                    )
                )
                .scalars()
                .all()
            )
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

        eval_result = self._policy_engine.evaluate(
            agent=AgentContext(
                id=agent.id if agent is not None else None,
                status=AgentStatus(agent.status) if agent is not None else None,
                authenticated=agent is not None,
            ),
            tool=ToolContext(
                name=tool.name if tool is not None else approval.tool_name,
                category=tool.category if tool is not None else None,
                exists=tool is not None,
                enabled=tool.enabled if tool is not None else False,
            ),
            request=EvaluationRequest(
                tool_name=approval.tool_name,
                action=approval.action,
                resource=approval.resource,
                arguments=approval.sanitized_arguments,
                correlation_id=approval.correlation_id,
            ),
            policies=policy_rules,
        )

        if eval_result.decision == PolicyDecision.DENY:
            raise AuthorizationError(
                f"Execution blocked on pre-execution re-evaluation: {eval_result.reason}",
                code="PRE_EXECUTION_POLICY_DENY",
            )

    async def execute_approved_request(
        self,
        session: AsyncSession,
        *,
        approval_id: UUID,
        settings: Settings,
        correlation_id: str | None = None,
    ) -> tuple[ApprovalRequest, VerificationResult, dict[str, Any] | None]:
        """Atomically claim an APPROVED request, re-check policy, execute once, and verify."""
        approval = await self.get_approval(session, approval_id)
        active_cid = correlation_id or approval.correlation_id

        if approval.status != ApprovalStatus.APPROVED.value:
            raise ConflictError(
                f"Approval request is in state '{approval.status}', expected 'approved'.",
                code="APPROVAL_NOT_EXECUTABLE",
            )

        now = datetime.now(UTC)
        if now >= approval.expires_at:
            exp_res = await session.execute(
                update(ApprovalRequest)
                .where(
                    ApprovalRequest.id == approval.id,
                    ApprovalRequest.status == ApprovalStatus.APPROVED.value,
                )
                .values(status=ApprovalStatus.EXPIRED.value)
            )
            if exp_res.rowcount and exp_res.rowcount > 0:
                await self._audit.record_event(
                    session,
                    correlation_id=active_cid,
                    agent_id=approval.agent_id,
                    tool_name=approval.tool_name,
                    action=approval.action,
                    resource=approval.resource,
                    decision=PolicyDecision.DENY,
                    reason="Approved request expired before execution.",
                    policy_id=approval.policy_id,
                    policy_version=approval.policy_version,
                    policy_metadata={"stage": "pre_execution_expiration"},
                    approval_id=approval.id,
                    reviewer_id=approval.reviewer_id,
                    reviewed_at=approval.reviewed_at,
                    execution_status=ExecutionStatus.EXPIRED,
                    verification_status=VerificationStatus.EXPIRED,
                    event_type=AuditEventType.APPROVAL_EXPIRED,
                    commit=True,
                )
            else:
                await session.commit()
            raise ConflictError("Approval request has expired.", code="APPROVAL_EXPIRED")

        # Atomic Compare-And-Swap execution claim prevents concurrent/duplicate execution
        claim_stmt = (
            update(ApprovalRequest)
            .where(
                ApprovalRequest.id == approval.id,
                ApprovalRequest.status == ApprovalStatus.APPROVED.value,
                ApprovalRequest.execution_claimed_at.is_(None),
            )
            .values(execution_claimed_at=now)
        )
        claim_res = await session.execute(claim_stmt)
        if not claim_res.rowcount or claim_res.rowcount == 0:
            await session.rollback()
            raise ConflictError(
                "Approval execution has already been claimed or completed.",
                code="DUPLICATE_APPROVAL_EXECUTION",
            )
        await session.commit()
        await session.refresh(approval)

        try:
            await self._reevaluate_before_execution(session, approval)
        except AuthorizationError as exc:
            await session.execute(
                update(ApprovalRequest)
                .where(ApprovalRequest.id == approval.id)
                .values(
                    status=ApprovalStatus.FAILED.value,
                    execution_result_reference={"blocked_reason": exc.message},
                )
            )
            await self._audit.record_event(
                session,
                correlation_id=active_cid,
                agent_id=approval.agent_id,
                tool_name=approval.tool_name,
                action=approval.action,
                resource=approval.resource,
                decision=PolicyDecision.DENY,
                reason=exc.message,
                policy_id=approval.policy_id,
                policy_version=approval.policy_version,
                policy_metadata={"stage": "pre_execution_reevaluation"},
                approval_id=approval.id,
                reviewer_id=approval.reviewer_id,
                reviewed_at=approval.reviewed_at,
                execution_status=ExecutionStatus.BLOCKED,
                verification_status=VerificationStatus.FAILED,
                event_type=AuditEventType.EXECUTION_FAILED,
                commit=True,
            )
            raise

        # Fail-closed audit write BEFORE running tool adapter
        await self._audit.record_event(
            session,
            correlation_id=active_cid,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            decision=PolicyDecision.ALLOW,
            reason="Executing administrator-approved request.",
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
            policy_metadata={"stage": "approved_execution_start"},
            approval_id=approval.id,
            reviewer_id=approval.reviewer_id,
            reviewed_at=approval.reviewed_at,
            execution_status=ExecutionStatus.STARTED,
            verification_status=VerificationStatus.APPROVED,
            event_type=AuditEventType.EXECUTION_STARTED,
            commit=True,
        )

        dispatch_res = await self._dispatcher.dispatch(
            session,
            correlation_id=active_cid,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            arguments=approval.sanitized_arguments,
            settings=settings,
            approval_id=approval.id,
        )
        exec_succeeded = dispatch_res.status == ExecutionStatus.EXECUTED

        exec_audit = await self._audit.record_event(
            session,
            correlation_id=active_cid,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            decision=PolicyDecision.ALLOW if exec_succeeded else PolicyDecision.DENY,
            reason=dispatch_res.summary,
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
            policy_metadata={"stage": "approved_execution_finish"},
            approval_id=approval.id,
            reviewer_id=approval.reviewer_id,
            reviewed_at=approval.reviewed_at,
            execution_metadata=dispatch_res.metadata,
            execution_status=dispatch_res.status,
            verification_status=(
                VerificationStatus.VERIFIED if exec_succeeded else VerificationStatus.FAILED
            ),
            event_type=(
                AuditEventType.EXECUTION_COMPLETED
                if exec_succeeded
                else AuditEventType.EXECUTION_FAILED
            ),
            commit=True,
        )

        verification = await self._verifier.verify_and_record(
            session,
            correlation_id=active_cid,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            arguments=approval.sanitized_arguments,
            execution_succeeded=exec_succeeded,
            execution_metadata=dispatch_res.metadata,
            execution_output=dispatch_res.output if exec_succeeded else None,
            settings=settings,
            audit_event_id=exec_audit.id,
            approval_id=approval.id,
        )

        final_approval_status = (
            ApprovalStatus.EXECUTED
            if exec_succeeded and verification.status != VerificationOutcome.FAILED
            else ApprovalStatus.FAILED
        )
        result_ref = {
            "verification_id": str(verification.verification_id),
            "verification_status": verification.status.value.upper(),
            "verification_method": verification.method,
            "metadata": dispatch_res.metadata,
        }
        await session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval.id)
            .values(
                status=final_approval_status.value,
                execution_result_reference=result_ref,
            )
        )

        await self._audit.record_event(
            session,
            correlation_id=active_cid,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            decision=PolicyDecision.ALLOW,
            reason=verification.message,
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
            policy_metadata={"verification_method": verification.method},
            approval_id=approval.id,
            reviewer_id=approval.reviewer_id,
            reviewed_at=approval.reviewed_at,
            verification_outcome=verification.status.value,
            execution_metadata={"verification_id": str(verification.verification_id)},
            execution_status=dispatch_res.status,
            verification_status=VerificationStatus(verification.status.value),
            event_type=AuditEventType.VERIFICATION_COMPLETED,
            commit=True,
        )
        await session.refresh(approval)
        verified_output = (
            dispatch_res.output if final_approval_status == ApprovalStatus.EXECUTED else None
        )
        return approval, verification, verified_output

    async def approve(
        self,
        session: AsyncSession,
        *,
        approval_id: UUID,
        reviewer_id: str,
        comment: str | None,
        execute_now: bool,
        settings: Settings,
    ) -> tuple[ApprovalRequest, VerificationResult | None, dict[str, Any] | None]:
        """Atomically approve a PENDING request and optionally execute + verify immediately."""
        approval = await self.get_approval(session, approval_id)
        await self._expire_if_elapsed(session, approval, reviewer_id=reviewer_id)

        now = datetime.now(UTC)
        stmt = (
            update(ApprovalRequest)
            .where(
                ApprovalRequest.id == approval.id,
                ApprovalRequest.status == ApprovalStatus.PENDING.value,
                ApprovalRequest.expires_at > now,
            )
            .values(
                status=ApprovalStatus.APPROVED.value,
                reviewed_at=now,
                reviewer_id=reviewer_id,
                reviewer_comment=comment,
            )
        )
        res = await session.execute(stmt)
        if not res.rowcount or res.rowcount == 0:
            await session.rollback()
            refreshed = await self.get_approval(session, approval_id)
            raise ConflictError(
                f"Approval request cannot be approved from state '{refreshed.status}'.",
                code="APPROVAL_ALREADY_RESOLVED",
            )

        await self._audit.record_event(
            session,
            correlation_id=approval.correlation_id,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            decision=PolicyDecision.ALLOW,
            reason=comment or "Administrator approved pending request.",
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
            policy_metadata={"stage": "human_approval"},
            approval_id=approval.id,
            reviewer_id=reviewer_id,
            reviewed_at=now,
            execution_status=ExecutionStatus.PENDING_APPROVAL,
            verification_status=VerificationStatus.APPROVED,
            event_type=AuditEventType.APPROVAL_APPROVED,
            commit=True,
        )
        await session.refresh(approval)

        if not execute_now:
            return approval, None, None

        return await self.execute_approved_request(
            session,
            approval_id=approval.id,
            settings=settings,
        )

    async def reject(
        self,
        session: AsyncSession,
        *,
        approval_id: UUID,
        reviewer_id: str,
        comment: str | None,
    ) -> ApprovalRequest:
        """Atomically reject a PENDING approval request (never executes)."""
        approval = await self.get_approval(session, approval_id)
        await self._expire_if_elapsed(session, approval, reviewer_id=reviewer_id)

        now = datetime.now(UTC)
        stmt = (
            update(ApprovalRequest)
            .where(
                ApprovalRequest.id == approval.id,
                ApprovalRequest.status == ApprovalStatus.PENDING.value,
                ApprovalRequest.expires_at > now,
            )
            .values(
                status=ApprovalStatus.REJECTED.value,
                reviewed_at=now,
                reviewer_id=reviewer_id,
                reviewer_comment=comment,
            )
        )
        res = await session.execute(stmt)
        if not res.rowcount or res.rowcount == 0:
            await session.rollback()
            refreshed = await self.get_approval(session, approval_id)
            raise ConflictError(
                f"Approval request cannot be rejected from state '{refreshed.status}'.",
                code="APPROVAL_ALREADY_RESOLVED",
            )

        await self._audit.record_event(
            session,
            correlation_id=approval.correlation_id,
            agent_id=approval.agent_id,
            tool_name=approval.tool_name,
            action=approval.action,
            resource=approval.resource,
            decision=PolicyDecision.DENY,
            reason=comment or "Administrator rejected pending request.",
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
            policy_metadata={"stage": "human_rejection"},
            approval_id=approval.id,
            reviewer_id=reviewer_id,
            reviewed_at=now,
            execution_status=ExecutionStatus.REJECTED,
            verification_status=VerificationStatus.REJECTED,
            event_type=AuditEventType.APPROVAL_REJECTED,
            commit=True,
        )
        await session.refresh(approval)
        return approval

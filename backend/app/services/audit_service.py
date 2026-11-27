"""Append-only chained audit logging service with fail-closed persistence guarantees."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
import weakref
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuditPersistenceError, ResourceNotFoundError
from app.core.logging import redact_secrets
from app.models.audit import AuditChainState, AuditEvent
from app.models.enums import AuditEventType, ExecutionStatus, PolicyDecision, VerificationStatus

logger = logging.getLogger("chaperone.audit")

GENESIS_PREV_HASH = "0" * 64
_PG_CHAIN_LOCK_KEY = 742819105
_SQLITE_CHAIN_LOCKS: weakref.WeakKeyDictionary[Any, asyncio.Lock] = weakref.WeakKeyDictionary()


def _get_sqlite_lock(session: AsyncSession) -> asyncio.Lock:
    bind = session.get_bind()
    lock = _SQLITE_CHAIN_LOCKS.get(bind)
    if lock is None:
        lock = asyncio.Lock()
        _SQLITE_CHAIN_LOCKS[bind] = lock
    return lock


def _fmt_utc_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return aware.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return 0.0 if value == 0.0 else value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return _fmt_utc_iso(value)
    if isinstance(value, dict):
        return {
            str(k): _normalize_canonical_value(v)
            for k, v in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list | tuple):
        return [_normalize_canonical_value(item) for item in value]
    return str(value)


def canonicalize_audit_payload(event: AuditEvent) -> str:
    """Serialize all immutable AuditEvent fields deterministically across SQLite and PG JSONB."""
    doc = _normalize_canonical_value(
        {
            "id": str(event.id),
            "chain_seq": event.chain_seq,
            "previous_hash": event.previous_hash,
            "event_type": event.event_type,
            "correlation_id": event.correlation_id,
            "agent_id": str(event.agent_id) if event.agent_id else None,
            "tool_name": event.tool_name,
            "action": event.action,
            "resource": event.resource,
            "decision": event.decision,
            "reason": event.reason,
            "policy_id": str(event.policy_id) if event.policy_id else None,
            "policy_version": event.policy_version,
            "policy_metadata": event.policy_metadata,
            "approval_id": str(event.approval_id) if event.approval_id else None,
            "reviewer_id": event.reviewer_id,
            "reviewed_at": _fmt_utc_iso(event.reviewed_at),
            "verification_outcome": event.verification_outcome,
            "execution_metadata": event.execution_metadata,
            "execution_status": event.execution_status,
            "verification_status": event.verification_status,
            "created_at": _fmt_utc_iso(event.created_at),
        }
    )
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_audit_record_hash(event: AuditEvent) -> str:
    """Compute a deterministic SHA-256 digest over canonical chained audit content."""
    return hashlib.sha256(canonicalize_audit_payload(event).encode("utf-8")).hexdigest()


class AuditService:
    """Append-only chained audit service. Exposes creation, listing, and integrity checks."""

    async def _lock_and_get_chain_state(self, session: AsyncSession) -> AuditChainState:
        dialect_name = session.get_bind().dialect.name
        if dialect_name == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": _PG_CHAIN_LOCK_KEY},
            )
            stmt = select(AuditChainState).where(AuditChainState.id == 1).with_for_update()
            state = (await session.execute(stmt)).scalar_one_or_none()
        else:
            stmt = select(AuditChainState).where(AuditChainState.id == 1)
            state = (await session.execute(stmt)).scalar_one_or_none()

        if state is not None:
            return state

        # Bootstrap chain head from existing latest chained row (or genesis)
        latest_stmt = (
            select(AuditEvent)
            .where(AuditEvent.chain_seq.is_not(None))
            .order_by(AuditEvent.chain_seq.desc())
            .limit(1)
        )
        latest_row = (await session.execute(latest_stmt)).scalar_one_or_none()
        init_seq = int(latest_row.chain_seq) if latest_row and latest_row.chain_seq else 0
        init_hash = (
            str(latest_row.record_hash)
            if latest_row and latest_row.record_hash
            else GENESIS_PREV_HASH
        )
        init_created = latest_row.created_at if latest_row else None

        state = AuditChainState(
            id=1,
            last_seq=init_seq,
            last_hash=init_hash,
            last_created_at=init_created,
            updated_at=datetime.now(UTC),
        )
        session.add(state)
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            refetched = (
                await session.execute(select(AuditChainState).where(AuditChainState.id == 1))
            ).scalar_one()
            return refetched
        return state

    async def _insert_chained_event(
        self,
        session: AsyncSession,
        *,
        correlation_id: str,
        agent_id: UUID | None,
        tool_name: str,
        action: str,
        resource: str,
        decision: PolicyDecision,
        reason: str,
        policy_id: UUID | None,
        policy_version: int | None,
        policy_metadata: dict[str, Any] | None,
        execution_status: ExecutionStatus,
        verification_status: VerificationStatus,
        event_type: AuditEventType,
        approval_id: UUID | None,
        reviewer_id: str | None,
        reviewed_at: datetime | None,
        verification_outcome: str | None,
        execution_metadata: dict[str, Any] | None,
        commit: bool,
    ) -> AuditEvent:
        safe_resource = redact_secrets(resource)[:1024]
        safe_reason = redact_secrets(reason)[:2000]
        event_id = uuid.uuid4()

        chain_state = await self._lock_and_get_chain_state(session)
        next_seq = chain_state.last_seq + 1
        prev_hash = chain_state.last_hash or GENESIS_PREV_HASH
        now = datetime.now(UTC)
        if chain_state.last_created_at is not None:
            last_dt = (
                chain_state.last_created_at.replace(tzinfo=UTC)
                if chain_state.last_created_at.tzinfo is None
                else chain_state.last_created_at.astimezone(UTC)
            )
            if now < last_dt:
                now = last_dt

        event = AuditEvent(
            id=event_id,
            chain_seq=next_seq,
            previous_hash=prev_hash,
            event_type=event_type.value,
            correlation_id=correlation_id[:64],
            agent_id=agent_id,
            tool_name=tool_name[:128],
            action=action[:64],
            resource=safe_resource,
            decision=decision.value,
            reason=safe_reason,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_metadata=policy_metadata,
            approval_id=approval_id,
            reviewer_id=reviewer_id[:128] if reviewer_id else None,
            reviewed_at=reviewed_at,
            verification_outcome=verification_outcome,
            execution_metadata=execution_metadata,
            execution_status=execution_status.value,
            verification_status=verification_status.value,
            created_at=now,
        )
        event.record_hash = compute_audit_record_hash(event)
        session.add(event)

        chain_state.last_seq = next_seq
        chain_state.last_hash = event.record_hash
        chain_state.last_created_at = now
        chain_state.updated_at = now

        try:
            if commit:
                await session.commit()
                await session.refresh(event)
            else:
                await session.flush()
        except SQLAlchemyError as exc:
            await session.rollback()
            logger.error(
                "Audit persistence failed; failing closed",
                extra={"correlation_id": correlation_id},
            )
            raise AuditPersistenceError() from exc
        return event

    async def record_event(
        self,
        session: AsyncSession,
        *,
        correlation_id: str,
        agent_id: UUID | None,
        tool_name: str,
        action: str,
        resource: str,
        decision: PolicyDecision,
        reason: str,
        policy_id: UUID | None,
        policy_version: int | None,
        policy_metadata: dict[str, Any] | None,
        execution_status: ExecutionStatus,
        verification_status: VerificationStatus,
        event_type: AuditEventType = AuditEventType.POLICY_EVALUATION,
        approval_id: UUID | None = None,
        reviewer_id: str | None = None,
        reviewed_at: datetime | None = None,
        verification_outcome: str | None = None,
        execution_metadata: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditEvent:
        """Persist a hash-chained immutable audit event; fail closed on any persistence error."""
        dialect_name = session.get_bind().dialect.name
        if dialect_name == "sqlite":
            lock = _get_sqlite_lock(session)
            async with lock:
                try:
                    return await self._insert_chained_event(
                        session,
                        correlation_id=correlation_id,
                        agent_id=agent_id,
                        tool_name=tool_name,
                        action=action,
                        resource=resource,
                        decision=decision,
                        reason=reason,
                        policy_id=policy_id,
                        policy_version=policy_version,
                        policy_metadata=policy_metadata,
                        execution_status=execution_status,
                        verification_status=verification_status,
                        event_type=event_type,
                        approval_id=approval_id,
                        reviewer_id=reviewer_id,
                        reviewed_at=reviewed_at,
                        verification_outcome=verification_outcome,
                        execution_metadata=execution_metadata,
                        commit=commit,
                    )
                except SQLAlchemyError as exc:
                    await session.rollback()
                    raise AuditPersistenceError() from exc

        try:
            return await self._insert_chained_event(
                session,
                correlation_id=correlation_id,
                agent_id=agent_id,
                tool_name=tool_name,
                action=action,
                resource=resource,
                decision=decision,
                reason=reason,
                policy_id=policy_id,
                policy_version=policy_version,
                policy_metadata=policy_metadata,
                execution_status=execution_status,
                verification_status=verification_status,
                event_type=event_type,
                approval_id=approval_id,
                reviewer_id=reviewer_id,
                reviewed_at=reviewed_at,
                verification_outcome=verification_outcome,
                execution_metadata=execution_metadata,
                commit=commit,
            )
        except SQLAlchemyError as exc:
            await session.rollback()
            raise AuditPersistenceError() from exc

    async def list_events(
        self,
        session: AsyncSession,
        *,
        page: int,
        page_size: int,
        agent_id: UUID | None = None,
        tool_name: str | None = None,
        decision: PolicyDecision | None = None,
        correlation_id: str | None = None,
        verification_status: VerificationStatus | None = None,
        event_type: AuditEventType | None = None,
        approval_id: UUID | None = None,
        order: Literal["asc", "desc"] = "desc",
    ) -> tuple[list[AuditEvent], int]:
        """List audit events with pagination, filtering, and chronological ordering."""
        filters = []
        if agent_id is not None:
            filters.append(AuditEvent.agent_id == agent_id)
        if tool_name is not None:
            filters.append(AuditEvent.tool_name == tool_name.strip().lower())
        if decision is not None:
            filters.append(AuditEvent.decision == decision.value)
        if correlation_id is not None:
            filters.append(AuditEvent.correlation_id == correlation_id.strip())
        if verification_status is not None:
            filters.append(AuditEvent.verification_status == verification_status.value)
        if event_type is not None:
            filters.append(AuditEvent.event_type == event_type.value)
        if approval_id is not None:
            filters.append(AuditEvent.approval_id == approval_id)

        count_stmt = select(func.count()).select_from(AuditEvent).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        offset = (page - 1) * page_size
        order_cols = (
            (AuditEvent.created_at.asc(), AuditEvent.chain_seq.asc().nulls_last(), AuditEvent.id.asc())
            if order == "asc"
            else (
                AuditEvent.created_at.desc(),
                AuditEvent.chain_seq.desc().nulls_last(),
                AuditEvent.id.asc(),
            )
        )
        stmt = select(AuditEvent).where(*filters).order_by(*order_cols).offset(offset).limit(page_size)
        items = list((await session.execute(stmt)).scalars().all())
        return items, total

    async def get_event(self, session: AsyncSession, event_id: UUID) -> AuditEvent:
        """Retrieve a single audit event by UUID."""
        stmt = select(AuditEvent).where(AuditEvent.id == event_id)
        event = (await session.execute(stmt)).scalar_one_or_none()
        if event is None:
            raise ResourceNotFoundError(f"Audit event '{event_id}' not found.")
        return event

    async def verify_integrity(
        self,
        session: AsyncSession,
        *,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Verify the complete audit hash chain from earliest available record onward."""
        stmt = select(AuditEvent).order_by(
            AuditEvent.chain_seq.asc().nulls_first(),
            AuditEvent.created_at.asc(),
            AuditEvent.id.asc(),
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        events = list((await session.execute(stmt)).scalars().all())
        chain_state = (
            await session.execute(select(AuditChainState).where(AuditChainState.id == 1))
        ).scalar_one_or_none()

        verified = 0
        chain_verified = 0
        legacy_unhashed = 0
        legacy_pre_chain = 0
        tampered_ids: list[UUID] = []
        broken_links: list[str] = []
        sequence_gaps: list[dict[str, int | str]] = []
        reordered_ids: list[UUID] = []

        saw_chained = False
        prev_chained: AuditEvent | None = None

        for ev in events:
            if ev.chain_seq is None:
                if saw_chained:
                    broken_links.append(f"interleaved_unchained:{ev.id}")
                if not ev.record_hash:
                    legacy_unhashed += 1
                else:
                    legacy_pre_chain += 1
                continue

            saw_chained = True
            expected_hash = compute_audit_record_hash(ev)
            row_hash_ok = ev.record_hash == expected_hash
            if row_hash_ok:
                verified += 1
                chain_verified += 1
            else:
                tampered_ids.append(ev.id)

            if prev_chained is None:
                if ev.chain_seq != 1:
                    sequence_gaps.append(
                        {"kind": "missing_head", "expected_seq": 1, "actual_seq": ev.chain_seq}
                    )
                if ev.previous_hash != GENESIS_PREV_HASH:
                    broken_links.append(str(ev.id))
            else:
                if ev.chain_seq != (prev_chained.chain_seq or 0) + 1:
                    sequence_gaps.append(
                        {
                            "kind": "sequence_gap",
                            "expected_seq": (prev_chained.chain_seq or 0) + 1,
                            "actual_seq": ev.chain_seq,
                        }
                    )
                if ev.previous_hash != prev_chained.record_hash:
                    broken_links.append(str(ev.id))
                ev_dt = (
                    ev.created_at.replace(tzinfo=UTC)
                    if ev.created_at.tzinfo is None
                    else ev.created_at.astimezone(UTC)
                )
                prev_dt = (
                    prev_chained.created_at.replace(tzinfo=UTC)
                    if prev_chained.created_at.tzinfo is None
                    else prev_chained.created_at.astimezone(UTC)
                )
                if ev_dt < prev_dt:
                    reordered_ids.append(ev.id)

            prev_chained = ev

        chain_complete = True
        head_seq = chain_state.last_seq if chain_state is not None else None
        head_hash = chain_state.last_hash if chain_state is not None else None

        if limit is None and chain_state is not None and chain_state.last_seq > 0:
            if prev_chained is None:
                chain_complete = False
                sequence_gaps.append(
                    {
                        "kind": "missing_all_chained",
                        "expected_seq": chain_state.last_seq,
                        "actual_seq": 0,
                    }
                )
            else:
                if prev_chained.chain_seq != chain_state.last_seq:
                    chain_complete = False
                    sequence_gaps.append(
                        {
                            "kind": "missing_tail",
                            "expected_seq": chain_state.last_seq,
                            "actual_seq": prev_chained.chain_seq or 0,
                        }
                    )
                if prev_chained.record_hash != chain_state.last_hash:
                    chain_complete = False
                    broken_links.append(f"tail_mismatch:{prev_chained.id}")

        intact = (
            len(tampered_ids) == 0
            and len(broken_links) == 0
            and len(sequence_gaps) == 0
            and len(reordered_ids) == 0
            and chain_complete
        )
        return {
            "checked": len(events),
            "verified": verified,
            "chain_verified": chain_verified,
            "legacy_unhashed": legacy_unhashed,
            "legacy_pre_chain": legacy_pre_chain,
            "tampered": len(tampered_ids),
            "tampered_ids": tampered_ids,
            "broken_links": broken_links,
            "sequence_gaps": sequence_gaps,
            "reordered_ids": reordered_ids,
            "head_seq": head_seq,
            "head_hash": head_hash,
            "chain_complete": chain_complete,
            "intact": intact,
        }

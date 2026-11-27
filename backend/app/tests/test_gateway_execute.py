"""Tests for gateway execution, non-invocation guarantees, idempotency, and audit fail-closed."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.file_adapter import FileToolAdapter
from app.core.config import Settings
from app.core.exceptions import AuditPersistenceError
from app.models.audit import AuditEvent
from app.models.enums import VerificationOutcome
from app.services.audit_service import AuditService
from app.verification.engine import VerificationEngine


@pytest.mark.asyncio
async def test_denied_and_approval_required_never_invoke_adapter(
    client: AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "spy-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_tool",
            "description": "Sandboxed file tool",
            "category": "filesystem",
            "risk_level": "medium",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "approve-notes-write",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "write",
            "resource_scope": "documents/*",
            "decision": "require_approval",
            "priority": 100,
        },
    )

    invocations = 0

    async def spy_execute(self, context):
        nonlocal invocations
        invocations += 1
        raise AssertionError("Adapter must NEVER be invoked on DENY or REQUIRE_APPROVAL")

    monkeypatch.setattr(FileToolAdapter, "execute", spy_execute)

    # 1. Default DENY does not invoke adapter
    deny_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"path": "documents/invoice.txt"},
        },
    )
    assert deny_resp.status_code == 403
    assert deny_resp.json()["status"] == "BLOCKED"
    assert invocations == 0

    # 2. REQUIRE_APPROVAL does not invoke adapter immediately
    approval_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "write",
            "resource": "documents/new.txt",
            "arguments": {"path": "documents/new.txt", "content": "Needs approval"},
        },
    )
    assert approval_resp.status_code == 202
    assert approval_resp.json()["status"] == "PENDING"
    assert invocations == 0


@pytest.mark.asyncio
async def test_failed_audit_write_never_allows_tool_execution(
    client: AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "audit-fail-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_tool",
            "description": "Sandboxed file tool",
            "category": "filesystem",
            "risk_level": "low",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-doc-read",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
        },
    )

    called = False

    async def spy_execute(self, context):
        nonlocal called
        called = True
        raise AssertionError("Adapter must not execute when audit persistence fails")

    async def failing_audit(*args, **kwargs):
        raise AuditPersistenceError()

    monkeypatch.setattr(FileToolAdapter, "execute", spy_execute)
    monkeypatch.setattr(AuditService, "record_event", failing_audit)

    resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"path": "documents/invoice.txt"},
        },
    )
    assert resp.status_code == 500
    assert called is False


@pytest.mark.asyncio
async def test_idempotency_key_executes_once_and_rejects_conflict(
    client: AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "idem-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_tool",
            "description": "Sandboxed file tool",
            "category": "filesystem",
            "risk_level": "low",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-doc-write",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "write",
            "resource_scope": "documents/*",
            "decision": "allow",
        },
    )

    real_execute = FileToolAdapter.execute
    exec_count = 0

    async def counted_execute(self, context):
        nonlocal exec_count
        exec_count += 1
        return await real_execute(self, context)

    monkeypatch.setattr(FileToolAdapter, "execute", counted_execute)

    payload = {
        "tool_name": "file_tool",
        "action": "write",
        "resource": "documents/idem.txt",
        "arguments": {"path": "documents/idem.txt", "content": "Idempotent content"},
    }
    first = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key, "Idempotency-Key": "idem-req-0001"},
        json=payload,
    )
    second = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key, "Idempotency-Key": "idem-req-0001"},
        json=payload,
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert exec_count == 1

    # Reusing same Idempotency-Key with altered payload returns 409 Conflict
    conflict = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key, "Idempotency-Key": "idem-req-0001"},
        json={
            "tool_name": "file_tool",
            "action": "write",
            "resource": "documents/other.txt",
            "arguments": {"path": "documents/other.txt", "content": "Different"},
        },
    )
    assert conflict.status_code == 409


@pytest.mark.asyncio
async def test_failed_verification_recorded_when_expected_state_missing(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "bad-verify-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_tool",
            "description": "Sandboxed file tool",
            "category": "filesystem",
            "risk_level": "medium",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-doc-write-verify",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "write",
            "resource_scope": "documents/*",
            "decision": "allow",
        },
    )

    # Simulate an adapter lying about success without actually writing the file!
    async def lying_adapter_execute(self, context):
        from app.adapters.base import AdapterExecutionResult

        return AdapterExecutionResult(
            success=True,
            summary="Fake claim of file write success",
            output={"path": context.resource},
            metadata={"path": context.resource},
        )

    monkeypatch.setattr(FileToolAdapter, "execute", lying_adapter_execute)

    resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key, "X-Correlation-ID": "corr-lying-adapter"},
        json={
            "tool_name": "file_tool",
            "action": "write",
            "resource": "documents/ghost.txt",
            "arguments": {"path": "documents/ghost.txt", "content": "Must exist on disk"},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "FAILED"
    assert body["verification"]["status"] == "FAILED"

    # Independent verification event persisted in audit log
    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.correlation_id == "corr-lying-adapter")
            )
        )
        .scalars()
        .all()
    )
    assert any(ev.verification_outcome == VerificationOutcome.FAILED.value for ev in events)

    # Direct VerificationEngine check: incorrect expected outcome fails verification
    engine = VerificationEngine()
    target = Path(test_settings.sandbox_dir) / "documents" / "invoice.txt"
    assert target.exists()
    bad_expected = await engine.verify_and_record(
        db_session,
        correlation_id="corr-direct-verify-fail",
        tool_name="file_tool",
        action="read",
        resource="documents/invoice.txt",
        arguments={"path": "documents/invoice.txt"},
        execution_succeeded=True,
        execution_metadata={},
        settings=test_settings,
        expected_override={"exists": False, "is_file": False},
    )
    assert bad_expected.status == VerificationOutcome.FAILED

"""Tests for human approval workflow: creation, rejection, expiry, replay, tampering, RBAC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.email_adapter import EmailToolAdapter
from app.approvals.models import ApprovalRequest
from app.models.mock_state import MockEmailRecord


async def _setup_email_approval_scenario(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> tuple[str, str]:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "approval-agent"},
    )
    assert agent_resp.status_code == 201
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    tool_resp = await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "email_tool",
            "description": "Mock email provider",
            "category": "communication",
            "risk_level": "high",
        },
    )
    assert tool_resp.status_code == 201

    policy_resp = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "approve-internal-email",
            "agent_id": agent_id,
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "*@company.com",
            "decision": "require_approval",
            "priority": 100,
        },
    )
    assert policy_resp.status_code == 201
    return agent_id, agent_key


@pytest.mark.asyncio
async def test_approval_creation_rejection_and_unauthorized_reviewer(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    _, agent_key = await _setup_email_approval_scenario(client, admin_headers)

    exec_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "finance@company.com",
            "arguments": {
                "to": "finance@company.com",
                "subject": "Quarterly Summary",
                "body": "Please review Q1 invoice.",
            },
        },
    )
    assert exec_resp.status_code == 202
    body = exec_resp.json()
    assert body["decision"] == "REQUIRE_APPROVAL"
    assert body["status"] == "PENDING"
    approval_id = body["approval_id"]

    # Unauthorized reviewer (no admin key or agent key) is blocked
    unauth_approve = await client.post(f"/api/v1/approvals/{approval_id}/approve")
    assert unauth_approve.status_code == 401
    agent_approve = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers={"X-Admin-Key": agent_key},
    )
    assert agent_approve.status_code == 401

    # Rejecting approval marks REJECTED and never sends mock email
    reject_resp = await client.post(
        f"/api/v1/approvals/{approval_id}/reject",
        headers=admin_headers,
        json={"comment": "Not authorized right now"},
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["approval"]["status"] == "rejected"

    emails = (await db_session.execute(select(MockEmailRecord))).scalars().all()
    assert emails == []

    # Re-approving a rejected request fails with 409
    reapprove = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    assert reapprove.status_code == 409


@pytest.mark.asyncio
async def test_expired_approval_is_rejected(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    _, agent_key = await _setup_email_approval_scenario(client, admin_headers)

    exec_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "ops@company.com",
            "arguments": {
                "to": "ops@company.com",
                "subject": "Ops Alert",
                "body": "Disk check",
            },
        },
    )
    approval_id = UUID(exec_resp.json()["approval_id"])

    await db_session.execute(
        update(ApprovalRequest)
        .where(ApprovalRequest.id == approval_id)
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=60))
    )
    await db_session.commit()

    approve_resp = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    assert approve_resp.status_code == 409
    assert approve_resp.json()["error"]["code"] == "APPROVAL_EXPIRED"

    detail = await client.get(f"/api/v1/approvals/{approval_id}", headers=admin_headers)
    assert detail.json()["status"] == "expired"


@pytest.mark.asyncio
async def test_duplicate_approval_execution_prevented_and_executes_once(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    _, agent_key = await _setup_email_approval_scenario(client, admin_headers)

    exec_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "cfo@company.com",
            "arguments": {
                "to": "cfo@company.com",
                "subject": "Invoice Approved",
                "body": "INV-2026-001 summary",
            },
        },
    )
    approval_id = exec_resp.json()["approval_id"]

    first = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
        json={"comment": "Approved once"},
    )
    assert first.status_code == 200
    assert first.json()["execution_status"] == "EXECUTED"
    assert first.json()["verification"]["status"] == "VERIFIED"

    # Second approval call is rejected; email count remains 1
    second = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    assert second.status_code == 409

    # Replaying execution via gateway with approval_id also fails with 409
    replay = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "cfo@company.com",
            "arguments": {
                "to": "cfo@company.com",
                "subject": "Invoice Approved",
                "body": "INV-2026-001 summary",
            },
            "approval_id": approval_id,
        },
    )
    assert replay.status_code == 409

    emails = (await db_session.execute(select(MockEmailRecord))).scalars().all()
    assert len(emails) == 1


@pytest.mark.asyncio
async def test_payload_tampering_after_approval_is_blocked(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    _, agent_key = await _setup_email_approval_scenario(client, admin_headers)

    exec_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "audit@company.com",
            "arguments": {
                "to": "audit@company.com",
                "subject": "Safe Report",
                "body": "Original approved body",
            },
        },
    )
    approval_id = exec_resp.json()["approval_id"]

    # Two-step approve (execute_now=False)
    approve_resp = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
        json={"execute_now": False, "comment": "Approved for agent execution"},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["approval"]["status"] == "approved"

    # Requester attempts to alter body after approval -> rejected!
    tamper_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "audit@company.com",
            "arguments": {
                "to": "audit@company.com",
                "subject": "Safe Report",
                "body": "Tampered malicious body!",
            },
            "approval_id": approval_id,
        },
    )
    assert tamper_resp.status_code == 403
    assert tamper_resp.json()["error"]["code"] == "PAYLOAD_TAMPERING_DETECTED"

    # Exact untampered payload succeeds once
    valid_exec = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "audit@company.com",
            "arguments": {
                "to": "audit@company.com",
                "subject": "Safe Report",
                "body": "Original approved body",
            },
            "approval_id": approval_id,
        },
    )
    assert valid_exec.status_code == 200
    assert valid_exec.json()["status"] == "EXECUTED"


@pytest.mark.asyncio
async def test_explicit_denial_cannot_be_approved_or_executed_after_policy_change(
    client: AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, agent_key = await _setup_email_approval_scenario(client, admin_headers)

    # Add explicit DENY at higher priority -> no approval created!
    deny_pol = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "explicit-deny-blocked-user",
            "agent_id": agent_id,
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "blocked@company.com",
            "decision": "deny",
            "priority": 500,
        },
    )
    assert deny_pol.status_code == 201

    blocked_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "blocked@company.com",
            "arguments": {
                "to": "blocked@company.com",
                "subject": "Test",
                "body": "Should be denied",
            },
        },
    )
    assert blocked_resp.status_code == 403
    assert blocked_resp.json()["decision"] == "DENY"
    assert blocked_resp.json()["approval_id"] is None

    # Even if an approval was requested BEFORE an explicit deny policy was added,
    # re-evaluation immediately before execution blocks it and never invokes adapter.
    pending_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "lateblock@company.com",
            "arguments": {
                "to": "lateblock@company.com",
                "subject": "Late Block",
                "body": "Should fail pre-exec recheck",
            },
        },
    )
    approval_id = pending_resp.json()["approval_id"]

    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "late-explicit-deny",
            "agent_id": agent_id,
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "lateblock@company.com",
            "decision": "deny",
            "priority": 900,
        },
    )

    called = False

    async def spy_execute(self, context):
        nonlocal called
        called = True
        raise AssertionError("Adapter must not execute when re-evaluation denies")

    monkeypatch.setattr(EmailToolAdapter, "execute", spy_execute)

    late_approve = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    assert late_approve.status_code == 403
    assert late_approve.json()["error"]["code"] == "PRE_EXECUTION_POLICY_DENY"
    assert called is False

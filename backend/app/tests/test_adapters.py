"""Tests for File, Email, and Database tool adapters and sandbox security controls."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterSecurityError, ExecutionContext
from app.adapters.database_adapter import DatabaseToolAdapter
from app.adapters.file_adapter import resolve_sandbox_target
from app.core.config import Settings
from app.models.mock_state import DemoInvoice, MockEmailRecord


@pytest.mark.asyncio
async def test_file_adapter_allowed_read_write_private_denied_traversal_and_symlink(
    client: AsyncClient,
    admin_headers: dict[str, str],
    test_settings: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "file-agent"},
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
            "name": "allow-docs-rw",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "*",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "deny-private",
            "agent_id": None,
            "tool_name": "file_tool",
            "action": "*",
            "resource_scope": "private/*",
            "decision": "deny",
            "priority": 500,
        },
    )

    # 1. Allowed read
    read_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/project_notes.txt",
            "arguments": {"path": "documents/project_notes.txt"},
        },
    )
    assert read_resp.status_code == 200
    assert read_resp.json()["status"] == "EXECUTED"
    assert "AXLY Chaperone" in read_resp.json()["output"]["content"]

    # 2. Allowed write + independent verification
    write_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "write",
            "resource": "documents/summary.txt",
            "arguments": {"path": "documents/summary.txt", "content": "Invoice INV-2026-001"},
        },
    )
    assert write_resp.status_code == 200
    assert write_resp.json()["status"] == "EXECUTED"
    assert write_resp.json()["verification"]["status"] == "VERIFIED"

    # 3. Private file denied
    priv_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "private/secrets.txt",
            "arguments": {"path": "private/secrets.txt"},
        },
    )
    assert priv_resp.status_code == 403
    assert priv_resp.json()["decision"] == "DENY"

    # 4. Path traversal & absolute path denied
    for bad_path in ("../outside.txt", "documents/../private/secrets.txt", "/etc/passwd"):
        bad_resp = await client.post(
            "/api/v1/gateway/execute",
            headers={"X-Agent-Key": agent_key},
            json={
                "tool_name": "file_tool",
                "action": "read",
                "resource": bad_path,
                "arguments": {"path": bad_path},
            },
        )
        assert bad_resp.status_code == 403
        assert bad_resp.json()["decision"] == "DENY"

    # 5. Symlink escape denied inside FileToolAdapter / resolve_sandbox_target
    sandbox_root = Path(test_settings.sandbox_dir)
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_text("TOP_SECRET", encoding="utf-8")
    symlink_candidate = sandbox_root / "documents" / "escape_link.txt"

    try:
        os.symlink(outside_file, symlink_candidate)
    except OSError:
        # Windows without Developer Mode privileges blocks unprivileged os.symlink:
        # simulate symlink detection deterministically on the target segment.
        original_islink = os.path.islink
        monkeypatch.setattr(
            os.path,
            "islink",
            lambda p: True if Path(p) == symlink_candidate else original_islink(p),
        )

    with pytest.raises(AdapterSecurityError):
        resolve_sandbox_target(sandbox_root, "documents/escape_link.txt")


@pytest.mark.asyncio
async def test_email_adapter_draft_and_approved_send(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "email-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "email_tool",
            "description": "Mock email tool",
            "category": "communication",
            "risk_level": "high",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-drafts",
            "agent_id": agent_id,
            "tool_name": "email_tool",
            "action": "create_draft",
            "resource_scope": "*@company.com",
            "decision": "allow",
            "priority": 100,
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "require-approval-send",
            "agent_id": agent_id,
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "*@company.com",
            "decision": "require_approval",
            "priority": 100,
        },
    )

    draft_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "create_draft",
            "resource": "team@company.com",
            "arguments": {
                "to": "team@company.com",
                "subject": "Draft Update",
                "body": "Initial summary draft.",
            },
        },
    )
    assert draft_resp.status_code == 200
    assert draft_resp.json()["output"]["status"] == "draft"
    assert draft_resp.json()["verification"]["status"] == "VERIFIED"

    send_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "team@company.com",
            "arguments": {
                "to": "team@company.com",
                "subject": "Final Update",
                "body": "Approved summary.",
            },
        },
    )
    assert send_resp.status_code == 202
    approval_id = send_resp.json()["approval_id"]

    approve_resp = await client.post(
        f"/api/v1/approvals/{approval_id}/approve",
        headers=admin_headers,
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["verification"]["status"] == "VERIFIED"

    sent_rows = (
        (await db_session.execute(select(MockEmailRecord).where(MockEmailRecord.status == "sent")))
        .scalars()
        .all()
    )
    assert len(sent_rows) == 1
    assert sent_rows[0].recipient == "team@company.com"


@pytest.mark.asyncio
async def test_database_adapter_crud_and_unauthorized_table_denied(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    test_settings: Settings,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "db-agent"},
    )
    agent_id = agent_resp.json()["id"]
    agent_key = agent_resp.json()["api_key"]

    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "database_tool",
            "description": "Structured demo table adapter",
            "category": "database",
            "risk_level": "medium",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-demo-invoices",
            "agent_id": agent_id,
            "tool_name": "database_tool",
            "action": "*",
            "resource_scope": "demo_invoices",
            "decision": "allow",
            "priority": 100,
        },
    )

    # 1. Insert
    create_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "create",
            "resource": "demo_invoices",
            "arguments": {
                "table": "demo_invoices",
                "data": {
                    "invoice_number": "INV-2026-001",
                    "vendor_name": "Acme Cloud",
                    "amount_inr": 45000,
                    "status": "pending",
                },
            },
        },
    )
    assert create_resp.status_code == 200
    assert create_resp.json()["status"] == "EXECUTED"
    assert create_resp.json()["verification"]["status"] == "VERIFIED"
    record_id = create_resp.json()["output"]["record_id"]

    # 2. Read
    read_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "read",
            "resource": "demo_invoices",
            "arguments": {
                "table": "demo_invoices",
                "filters": {"invoice_number": "INV-2026-001"},
            },
        },
    )
    assert read_resp.status_code == 200
    assert read_resp.json()["output"]["count"] == 1

    # 3. Update
    update_resp = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "update",
            "resource": "demo_invoices",
            "arguments": {
                "table": "demo_invoices",
                "record_id": record_id,
                "data": {"status": "approved"},
            },
        },
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["verification"]["status"] == "VERIFIED"

    row = (
        await db_session.execute(
            select(DemoInvoice).where(DemoInvoice.invoice_number == "INV-2026-001")
        )
    ).scalar_one()
    assert row.status == "approved"

    # 4. Unauthorized table denied by policy AND rejected at adapter level
    unauth_table = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "read",
            "resource": "agents",
            "arguments": {"table": "agents"},
        },
    )
    assert unauth_table.status_code == 403

    adapter = DatabaseToolAdapter()
    with pytest.raises(AdapterSecurityError):
        await adapter.execute(
            ExecutionContext(
                correlation_id="direct-check",
                agent_id=uuid4(),
                tool_name="database_tool",
                action="read",
                resource="audit_events",
                arguments={"table": "audit_events"},
                session=db_session,
                settings=test_settings,
            )
        )

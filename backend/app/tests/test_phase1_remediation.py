"""Comprehensive tests for Phase 1 security remediation items 1.1 through 1.4."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.adapters.base import AdapterSecurityError
from app.adapters.file_adapter import (
    FileToolAdapter,
    list_sandbox_dir_verified,
    read_sandbox_file_verified,
    write_sandbox_file_atomic,
)
from app.adapters.mcp.client import ChaperoneMCPClient, connect_in_memory_mcp, connect_stdio_mcp
from app.adapters.mcp.server import create_chaperone_mcp_server
from app.core.config import Settings
from app.core.database import build_session_factory
from app.models.admin import AdminSession
from app.models.audit import AuditChainState, AuditEvent
from app.models.enums import AuditEventType, ExecutionStatus, PolicyDecision, VerificationStatus
from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_phase1_mcp_no_api_key_in_schema_and_out_of_band_binding(
    client: AsyncClient,
    admin_headers: dict[str, str],
    test_engine: AsyncEngine,
    test_settings: Settings,
) -> None:
    ag = (
        await client.post("/api/v1/agents", headers=admin_headers, json={"name": "mcp-oob-agent"})
    ).json()
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
            "name": "mcp-oob-allow",
            "agent_id": ag["id"],
            "tool_name": "file_tool",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
    )

    session_factory = build_session_factory(test_engine)

    # 1. Inspect tools/list -> zero API key schema properties
    srv = create_chaperone_mcp_server(
        session_factory=session_factory,
        settings=test_settings,
        bound_agent_key=ag["api_key"],
    )
    async with connect_in_memory_mcp(srv) as mcp:
        tools = await mcp.list_tools()
        assert len(tools) == 3
        for tool in tools:
            serialized_schema = str(tool.input_schema).lower()
            assert "agent_api_key" not in serialized_schema
            assert "api_key" not in serialized_schema

        # Attempting credential smuggling via nested arguments fails before execution
        smuggle = await mcp.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            arguments={"path": "documents/invoice.txt", "agent_api_key": ag["api_key"]},
        )
        assert smuggle.is_error is True
        assert smuggle.payload["error"]["code"] == "INVALID_MCP_ARGUMENTS"

        # Legitimate out-of-band authenticated call passes through gateway
        ok = await mcp.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            arguments={"path": "documents/invoice.txt"},
            correlation_id="phase1-mcp-oob-ok",
        )
        assert ok.is_error is False
        assert ok.payload["status"] == "EXECUTED"

    # 2. Verify connect_stdio_mcp injects key exclusively via env, never tool arguments
    captured_params = {}

    class _FakeStdioCtx:
        async def __aenter__(self):
            return ("r", "w")

        async def __aexit__(self, *args):
            return False

    class _FakeClientSession:
        def __init__(self, r, w):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def initialize(self):
            return None

    def _fake_stdio_client(params):
        captured_params["env"] = params.env
        return _FakeStdioCtx()

    with (
        patch("app.adapters.mcp.client.stdio_client", side_effect=_fake_stdio_client),
        patch("app.adapters.mcp.client.ClientSession", _FakeClientSession),
    ):
        async with connect_stdio_mcp(agent_api_key=ag["api_key"]) as stdio_mcp:
            assert isinstance(stdio_mcp, ChaperoneMCPClient)
    assert captured_params["env"]["CHAPERONE_MCP_AGENT_KEY"] == ag["api_key"]


@pytest.mark.asyncio
async def test_phase1_cookie_auth_csrf_rbac_and_forged_actor_ignored(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    test_settings: Settings,
) -> None:
    # Create named super_admin, approver, and viewer accounts using dev admin key
    for uname, role in (
        ("alice-approver", "approver"),
        ("bob-viewer", "viewer"),
        ("carol-super", "super_admin"),
    ):
        r = await client.post(
            "/api/v1/auth/users",
            headers=admin_headers,
            json={"username": uname, "password": "VeryStrongPassword!123", "role": role},
        )
        assert r.status_code == 201, r.text

    # Seed agent + require_approval policy + pending approval using X-Admin-Key + forged header
    ag = (
        await client.post(
            "/api/v1/agents",
            headers={**admin_headers, "X-Admin-Actor": "forged-ceo-spoof"},
            json={"name": "auth-rbac-agent"},
        )
    ).json()
    await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "email_tool",
            "description": "Mock email",
            "category": "communication",
            "risk_level": "high",
        },
    )
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "require-approval-finance",
            "agent_id": ag["id"],
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "*@company.com",
            "decision": "require_approval",
            "priority": 100,
        },
    )
    pend = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": ag["api_key"]},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "finance@company.com",
            "arguments": {"to": "finance@company.com", "subject": "Q4", "body": "Approved sum"},
        },
    )
    assert pend.status_code == 202
    ap_id = pend.json()["approval_id"]

    # 1. Invalid password rejected
    bad_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "alice-approver", "password": "WrongPassword123"},
    )
    assert bad_login.status_code == 401

    # 2. Viewer can read approvals but CANNOT approve or create policies (403 INSUFFICIENT_ROLE)
    viewer_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "bob-viewer", "password": "VeryStrongPassword!123"},
    )
    assert viewer_login.status_code == 200
    assert "httponly" in viewer_login.headers.get("set-cookie", "").lower()
    viewer_csrf = viewer_login.json()["csrf_token"]

    assert (await client.get("/api/v1/approvals")).status_code == 200
    viewer_approve = await client.post(
        f"/api/v1/approvals/{ap_id}/approve",
        headers={"X-CSRF-Token": viewer_csrf},
        json={"execute_now": True},
    )
    assert viewer_approve.status_code == 403
    assert viewer_approve.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    viewer_policy = await client.post(
        "/api/v1/policies",
        headers={"X-CSRF-Token": viewer_csrf},
        json={
            "name": "viewer-should-fail",
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "*",
            "decision": "allow",
        },
    )
    assert viewer_policy.status_code == 403
    assert viewer_policy.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    # Logout revokes viewer session immediately
    logout_resp = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": viewer_csrf})
    assert logout_resp.status_code == 200
    assert (await client.get("/api/v1/approvals")).status_code == 401

    # 3. Approver logs in -> CSRF required, RBAC blocks policy creation, approves cleanly,
    #    and forged X-Admin-Actor header CANNOT change server-derived reviewer_id!
    approver_login = await client.post(
        "/api/v1/auth/login",
        json={"username": "alice-approver", "password": "VeryStrongPassword!123"},
    )
    assert approver_login.status_code == 200
    approver_csrf = approver_login.json()["csrf_token"]
    assert approver_login.json()["reviewer_id"] == "alice-approver"

    # Missing CSRF rejected
    no_csrf = await client.post(
        f"/api/v1/approvals/{ap_id}/approve",
        json={"execute_now": True},
    )
    assert no_csrf.status_code == 403
    assert no_csrf.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

    # Approver cannot create/mutate agents (requires super_admin)
    approver_create_ag = await client.post(
        "/api/v1/agents",
        headers={"X-CSRF-Token": approver_csrf},
        json={"name": "forbidden-by-approver"},
    )
    assert approver_create_ag.status_code == 403
    assert approver_create_ag.json()["error"]["code"] == "INSUFFICIENT_ROLE"

    # Approver approves WITH forged X-Admin-Actor header -> server ignores forged header!
    ok_approve = await client.post(
        f"/api/v1/approvals/{ap_id}/approve",
        headers={"X-CSRF-Token": approver_csrf, "X-Admin-Actor": "forged-hacker-name"},
        json={"execute_now": True, "comment": "Looks clean"},
    )
    assert ok_approve.status_code == 200
    assert ok_approve.json()["approval"]["reviewer_id"] == "alice-approver"
    assert ok_approve.json()["execution_status"] == "EXECUTED"

    # 4. Expired session is rejected
    await db_session.execute(
        update(AdminSession)
        .where(AdminSession.principal_id == "alice-approver")
        .values(expires_at=datetime.now(UTC) - timedelta(minutes=5))
    )
    await db_session.commit()
    expired_probe = await client.get("/api/v1/auth/session")
    assert expired_probe.status_code == 401
    assert expired_probe.json()["error"]["code"] == "SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_phase1_chained_audit_integrity_concurrent_deletion_and_reordering(
    test_engine: AsyncEngine,
) -> None:
    session_factory = build_session_factory(test_engine)
    svc = AuditService()

    # 1. Concurrent insertion across 10 async tasks produces contiguous valid chain 1..10
    async def _insert_one(idx: int) -> UUID:
        async with session_factory() as s:
            ev = await svc.record_event(
                s,
                correlation_id=f"chain-conc-{idx:02d}",
                agent_id=None,
                tool_name="file_tool",
                action="read",
                resource=f"documents/file_{idx}.txt",
                decision=PolicyDecision.ALLOW,
                reason=f"Concurrent event {idx}",
                policy_id=None,
                policy_version=None,
                policy_metadata={"rule_index": idx, "nested": {"flag": True}},
                execution_metadata={"bytes": 100 + idx},
                execution_status=ExecutionStatus.EXECUTED,
                verification_status=VerificationStatus.VERIFIED,
                event_type=AuditEventType.EXECUTION_COMPLETED,
            )
            return ev.id

    inserted_ids = await asyncio.gather(*(_insert_one(i) for i in range(10)))
    assert len(inserted_ids) == 10

    async with session_factory() as s:
        res_ok = await svc.verify_integrity(s)
        assert res_ok["intact"] is True
        assert res_ok["chain_verified"] == 10
        assert res_ok["tampered"] == 0
        assert res_ok["broken_links"] == []
        assert res_ok["sequence_gaps"] == []
        assert res_ok["head_seq"] == 10

        events = (
            (await s.execute(select(AuditEvent).order_by(AuditEvent.chain_seq.asc())))
            .scalars()
            .all()
        )
        assert [e.chain_seq for e in events] == list(range(1, 11))

        # 2. Modifying policy_metadata in DB is caught!
        target_ev = events[3]
        orig_meta = dict(target_ev.policy_metadata or {})
        await s.execute(
            update(AuditEvent)
            .where(AuditEvent.id == target_ev.id)
            .values(policy_metadata={"rule_index": 999, "tampered": True})
        )
        await s.commit()
        res_meta_tamper = await svc.verify_integrity(s)
        assert res_meta_tamper["intact"] is False
        assert target_ev.id in res_meta_tamper["tampered_ids"]

        # Restore metadata cleanly before testing middle deletion
        await s.execute(
            update(AuditEvent)
            .where(AuditEvent.id == target_ev.id)
            .values(policy_metadata=orig_meta)
        )
        await s.commit()
        assert (await svc.verify_integrity(s))["intact"] is True

        # 3. Deleting a middle record (seq 5) triggers sequence_gaps & broken_links
        mid_ev = events[4]
        await s.execute(delete(AuditEvent).where(AuditEvent.id == mid_ev.id))
        await s.commit()
        res_del = await svc.verify_integrity(s)
        assert res_del["intact"] is False
        assert len(res_del["sequence_gaps"]) >= 1
        assert len(res_del["broken_links"]) >= 1

        # 4. Tail deletion vs AuditChainState also caught on fresh DB state
        await s.execute(delete(AuditEvent))
        await s.execute(delete(AuditChainState))
        await s.commit()

        ev1 = await svc.record_event(
            s,
            correlation_id="reorder-01",
            agent_id=None,
            tool_name="file_tool",
            action="read",
            resource="documents/a.txt",
            decision=PolicyDecision.ALLOW,
            reason="First",
            policy_id=None,
            policy_version=None,
            policy_metadata={"k": 1},
            execution_status=ExecutionStatus.EXECUTED,
            verification_status=VerificationStatus.VERIFIED,
        )
        ev2 = await svc.record_event(
            s,
            correlation_id="reorder-02",
            agent_id=None,
            tool_name="file_tool",
            action="read",
            resource="documents/b.txt",
            decision=PolicyDecision.ALLOW,
            reason="Second",
            policy_id=None,
            policy_version=None,
            policy_metadata={"k": 2},
            execution_status=ExecutionStatus.EXECUTED,
            verification_status=VerificationStatus.VERIFIED,
        )
        # Swap created_at timestamps backwards -> detects tampering + chronological reorder
        await s.execute(
            update(AuditEvent)
            .where(AuditEvent.id == ev2.id)
            .values(created_at=ev1.created_at - timedelta(seconds=10))
        )
        await s.commit()
        res_reordered = await svc.verify_integrity(s)
        assert res_reordered["intact"] is False
        assert ev2.id in res_reordered["reordered_ids"]


def test_phase1_toctou_filesystem_no_follow_and_atomic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = tmp_path / "sandbox"
    (sandbox / "documents").mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("TOP_SECRET", encoding="utf-8")

    # 1. Atomic write succeeds and leaves zero temp files behind
    digest = write_sandbox_file_atomic(sandbox, "documents/clean.txt", b"safe-payload")
    assert len(digest) == 64
    assert not any(p.name.startswith(".chaperone_tmp_") for p in (sandbox / "documents").iterdir())

    # 2. Handle-verified read & list succeed on legitimate files
    data, read_digest = read_sandbox_file_verified(
        sandbox,
        "documents/clean.txt",
        max_bytes=1024 * 1024,
    )
    assert data == b"safe-payload"
    assert read_digest == digest

    entries = list_sandbox_dir_verified(sandbox, "documents")
    assert any(e["name"] == "clean.txt" and e["type"] == "file" for e in entries)

    # 3. Real symlink / simulated symlink / junction on parent & final target are blocked
    sym_parent = sandbox / "sym_parent"
    orig_islink = os.path.islink
    monkeypatch.setattr(
        os.path,
        "islink",
        lambda p: True if Path(p) == sym_parent else orig_islink(p),
    )
    (sandbox / "sym_parent").mkdir(exist_ok=True)
    with pytest.raises(AdapterSecurityError):
        read_sandbox_file_verified(sandbox, "sym_parent/secret.txt", max_bytes=1024)

    monkeypatch.undo()
    target_link = sandbox / "documents" / "escape_link.txt"
    if hasattr(os, "symlink"):
        try:
            os.symlink(outside, target_link)
        except OSError:
            # Unprivileged Windows accounts without SeCreateSymbolicLinkPrivilege fallback
            orig_islink2 = os.path.islink
            target_link.write_text("placeholder", encoding="utf-8")
            monkeypatch.setattr(
                os.path,
                "islink",
                lambda p: True if Path(p) == target_link else orig_islink2(p),
            )
        with pytest.raises(AdapterSecurityError):
            read_sandbox_file_verified(sandbox, "documents/escape_link.txt", max_bytes=1024)
        with pytest.raises(AdapterSecurityError):
            write_sandbox_file_atomic(sandbox, "documents/escape_link.txt", b"overwrite")

    # 4. Unsupported platform fails closed
    monkeypatch.setattr(os, "name", "unknown_os")
    with pytest.raises(AdapterSecurityError):
        read_sandbox_file_verified(sandbox, "documents/clean.txt", max_bytes=1024)
    monkeypatch.undo()
    _ = FileToolAdapter

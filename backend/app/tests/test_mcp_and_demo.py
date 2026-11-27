"""Tests for MCP server/client integration, independent verification, and prompt-injection demo."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.adapters.file_adapter import FileToolAdapter
from app.adapters.mcp.client import connect_in_memory_mcp
from app.adapters.mcp.server import create_chaperone_mcp_server
from app.core.config import Settings
from app.core.database import build_session_factory
from app.demo.prompt_injection_demo import run_prompt_injection_demo
from app.models.enums import VerificationOutcome
from app.verification.engine import VerificationEngine


@pytest.mark.asyncio
async def test_mcp_server_registration_auth_policy_and_errors(
    client: AsyncClient,
    admin_headers: dict[str, str],
    test_engine: AsyncEngine,
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "mcp-agent"},
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
            "name": "mcp-allow-docs",
            "agent_id": agent_id,
            "tool_name": "file_tool",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
    )

    session_factory = build_session_factory(test_engine)
    mcp_server = create_chaperone_mcp_server(
        session_factory=session_factory,
        settings=test_settings,
    )

    async with connect_in_memory_mcp(mcp_server) as mcp_client:
        # 1. Tool registration check
        tools = await mcp_client.list_tools()
        tool_names = {tool.name for tool in tools}
        assert {"file_tool", "email_tool", "database_tool"} == tool_names

        # 2. Valid call executes through gateway & verifies
        valid_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            arguments={"path": "documents/invoice.txt"},
            agent_api_key=agent_key,
            correlation_id="mcp-valid-call-001",
        )
        assert valid_res.is_error is False
        assert valid_res.payload["status"] == "EXECUTED"
        assert valid_res.payload["correlation_id"] == "mcp-valid-call-001"
        assert valid_res.payload["verification"]["status"] == "VERIFIED"

        # 3. Invalid call (unknown tool and malformed action) handled safely
        unknown_res = await mcp_client.call_tool(
            tool_name="shell_exec",
            action="run",
            resource="/bin/sh",
            agent_api_key=agent_key,
        )
        assert unknown_res.is_error is True
        assert unknown_res.payload["error"]["code"] == "UNKNOWN_TOOL"

        malformed_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="exec_shell",
            resource="documents/invoice.txt",
            agent_api_key=agent_key,
        )
        assert malformed_res.is_error is True
        assert malformed_res.payload["error"]["code"] == "INVALID_MCP_ARGUMENTS"

        # 4. Unauthorized MCP call rejected & audited
        unauth_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            agent_api_key="axly_ag_0000000000000000_invalidinvalidinvalidinvalidinvalid",
            correlation_id="mcp-unauth-002",
        )
        assert unauth_res.is_error is True
        assert unauth_res.payload["error"]["code"] == "AUTHENTICATION_FAILED"

        # 5. Policy engine enforces DENY on private/secrets.txt and never invokes adapter
        real_exec = FileToolAdapter.execute
        called_private = False

        async def spy_execute(self, context):
            nonlocal called_private
            if "private" in context.resource:
                called_private = True
            return await real_exec(self, context)

        monkeypatch.setattr(FileToolAdapter, "execute", spy_execute)

        denied_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="private/secrets.txt",
            arguments={"path": "private/secrets.txt"},
            agent_api_key=agent_key,
            correlation_id="mcp-denied-003",
        )
        assert denied_res.is_error is True
        assert denied_res.payload["decision"] == "DENY"
        assert denied_res.payload["status"] == "BLOCKED"
        assert called_private is False

    # Verify MCP audit trail propagated correlation IDs cleanly
    audit_resp = await client.get(
        "/api/v1/audit-events?correlation_id=mcp-unauth-002",
        headers=admin_headers,
    )
    assert audit_resp.status_code == 200
    assert audit_resp.json()["total"] == 1


@pytest.mark.asyncio
async def test_verification_engine_confirms_and_rejects_mismatched_outcomes(
    db_session: AsyncSession,
    test_settings: Settings,
) -> None:
    verifier = VerificationEngine()
    target_path = Path(test_settings.sandbox_dir) / "documents" / "verify_probe.txt"
    target_path.write_text("hello verification", encoding="utf-8")

    ok = await verifier.verify_and_record(
        db_session,
        correlation_id="verify-ok-1",
        tool_name="file_tool",
        action="write",
        resource="documents/verify_probe.txt",
        arguments={"path": "documents/verify_probe.txt", "content": "hello verification"},
        execution_succeeded=True,
        execution_metadata={},
        settings=test_settings,
    )
    assert ok.status == VerificationOutcome.VERIFIED

    mismatch = await verifier.verify_and_record(
        db_session,
        correlation_id="verify-bad-2",
        tool_name="file_tool",
        action="write",
        resource="documents/verify_probe.txt",
        arguments={"path": "documents/verify_probe.txt", "content": "completely different content"},
        execution_succeeded=True,
        execution_metadata={},
        settings=test_settings,
    )
    assert mismatch.status == VerificationOutcome.FAILED


@pytest.mark.asyncio
async def test_prompt_injection_demo_end_to_end(
    test_engine: AsyncEngine,
    test_settings: Settings,
) -> None:
    session_factory = build_session_factory(test_engine)
    report = await run_prompt_injection_demo(
        session_factory=session_factory,
        settings=test_settings,
    )

    assert report.prompt_injection_signal_detected is True
    assert "INV-2026-001" in report.invoice_summary
    assert "45000 INR" in report.invoice_summary
    assert report.permitted_read_outcome["status"] == "EXECUTED"
    assert report.blocked_private_read_outcome["decision"] == "DENY"
    assert report.blocked_private_read_outcome["status"] == "BLOCKED"
    assert report.blocked_exfil_email_outcome["decision"] == "DENY"
    assert report.blocked_exfil_email_outcome["status"] == "BLOCKED"
    assert report.approval_requested_outcome["decision"] == "REQUIRE_APPROVAL"
    assert report.approval_requested_outcome["status"] == "PENDING"
    assert report.approved_execution_status == "executed"
    assert report.approved_verification_status == "verified"
    assert report.audit_event_count >= 7
    assert report.secrets_leaked is False

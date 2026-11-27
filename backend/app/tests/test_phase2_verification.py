"""Phase 2 tests for independent file-read digest and directory-listing verification."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterExecutionResult
from app.adapters.file_adapter import FileToolAdapter
from app.core.config import Settings
from app.models.enums import VerificationOutcome
from app.verification.engine import VerificationEngine
from app.verification.models import VerificationRecord


@pytest.mark.asyncio
async def test_phase2_verification_catches_fake_read_and_incomplete_directory_listings(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ag = (
        await client.post("/api/v1/agents", headers=admin_headers, json={"name": "verif-p2-agent"})
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
            "name": "allow-all-docs-p2",
            "agent_id": ag["id"],
            "tool_name": "file_tool",
            "action": "*",
            "resource_scope": "*",
            "decision": "allow",
            "priority": 100,
        },
    )

    # 1. Legitimate read passes content SHA-256 verification without leaking file content in DB
    ok_read = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": ag["api_key"], "X-Correlation-ID": "p2-ok-read-01"},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/project_notes.txt",
            "arguments": {"path": "documents/project_notes.txt"},
        },
    )
    assert ok_read.status_code == 200
    assert ok_read.json()["status"] == "EXECUTED"
    assert ok_read.json()["verification"]["status"] == "VERIFIED"

    rec_read = (
        await db_session.execute(
            select(VerificationRecord).where(VerificationRecord.correlation_id == "p2-ok-read-01")
        )
    ).scalar_one()
    assert rec_read.verification_method == "sandbox_file_read_digest_check"
    assert "AXLY Chaperone Phase 2 Project Notes" not in str(rec_read.observed_outcome)

    # 2. Legitimate list passes full entries metadata & digest verification
    ok_list = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": ag["api_key"], "X-Correlation-ID": "p2-ok-list-02"},
        json={
            "tool_name": "file_tool",
            "action": "list",
            "resource": "documents",
            "arguments": {"path": "documents"},
        },
    )
    assert ok_list.status_code == 200
    assert ok_list.json()["status"] == "EXECUTED"
    assert ok_list.json()["verification"]["status"] == "VERIFIED"

    # 3. Fake adapter returning altered read contents MUST fail verification
    async def fake_bad_read(self: FileToolAdapter, context):
        return AdapterExecutionResult(
            success=True,
            summary="Fake read response",
            output={"path": context.resource, "content": "FORGED_CONTENT", "size_bytes": 14},
            metadata={"path": context.resource},
        )

    monkeypatch.setattr(FileToolAdapter, "execute", fake_bad_read)
    bad_read = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": ag["api_key"], "X-Correlation-ID": "p2-bad-read-03"},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"path": "documents/invoice.txt"},
        },
    )
    assert bad_read.status_code == 200
    assert bad_read.json()["status"] == "FAILED"
    assert bad_read.json()["verification"]["status"] == "FAILED"

    # 4. Fake adapter returning incomplete directory entries MUST fail verification
    async def fake_incomplete_list(self: FileToolAdapter, context):
        return AdapterExecutionResult(
            success=True,
            summary="Truncated listing hiding files",
            output={
                "directory": context.resource,
                "entries": [{"name": "invoice.txt", "type": "file", "size_bytes": 10}],
            },
            metadata={"directory": context.resource, "entry_count": 1},
        )

    monkeypatch.setattr(FileToolAdapter, "execute", fake_incomplete_list)
    bad_list = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": ag["api_key"], "X-Correlation-ID": "p2-bad-list-04"},
        json={
            "tool_name": "file_tool",
            "action": "list",
            "resource": "documents",
            "arguments": {"path": "documents"},
        },
    )
    assert bad_list.status_code == 200
    assert bad_list.json()["status"] == "FAILED"
    assert bad_list.json()["verification"]["status"] == "FAILED"

    # 5. Direct VerificationEngine with None output returns INCONCLUSIVE rather than VERIFIED
    verifier = VerificationEngine()
    inc = await verifier.verify_and_record(
        db_session,
        correlation_id="p2-inconclusive-05",
        tool_name="file_tool",
        action="read",
        resource="documents/invoice.txt",
        arguments={"path": "documents/invoice.txt"},
        execution_succeeded=True,
        execution_metadata={},
        execution_output=None,
        settings=test_settings,
    )
    assert inc.status == VerificationOutcome.INCONCLUSIVE
    _ = Path(test_settings.sandbox_dir)

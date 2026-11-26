"""Integration tests for Gateway evaluation, audit persistence, and operational probes."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.config import Settings
from app.main import create_app
from app.models.audit import AuditEvent
from app.models.enums import ExecutionStatus, PolicyDecision, VerificationStatus
from app.services.audit_service import AuditService


async def _bootstrap_agent_and_tool(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> tuple[str, str]:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "gateway-agent"},
    )
    assert agent_resp.status_code == 201
    agent_id = agent_resp.json()["id"]
    raw_key = agent_resp.json()["api_key"]

    tool_resp = await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_reader",
            "description": "Reads workspace documents",
            "category": "filesystem",
            "risk_level": "medium",
            "enabled": True,
        },
    )
    assert tool_resp.status_code == 201
    return agent_id, raw_key


@pytest.mark.asyncio
async def test_gateway_evaluation_persists_audit_and_never_executes(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    agent_id, raw_key = await _bootstrap_agent_and_tool(client, admin_headers)

    policy_resp = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-invoices",
            "agent_id": agent_id,
            "tool_name": "file_reader",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
    )
    assert policy_resp.status_code == 201
    policy_id = policy_resp.json()["id"]

    eval_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={
            "X-Agent-Key": raw_key,
            "X-Correlation-ID": "corr-gateway-12345",
        },
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"path": "documents/invoice.txt"},
        },
    )
    assert eval_resp.status_code == 200
    assert eval_resp.headers["X-Correlation-ID"] == "corr-gateway-12345"
    body = eval_resp.json()
    assert body["correlation_id"] == "corr-gateway-12345"
    assert body["decision"] == "ALLOW"
    assert body["matched_policy_id"] == policy_id
    assert body["agent_id"] == agent_id
    assert body["execution_status"] == "not_executed"

    # Verify persisted audit record
    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.correlation_id == "corr-gateway-12345")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    event = events[0]
    assert event.agent_id == UUID(agent_id)
    assert event.tool_name == "file_reader"
    assert event.action == "read"
    assert event.resource == "documents/invoice.txt"
    assert event.decision == PolicyDecision.ALLOW.value
    assert event.policy_id == UUID(policy_id)
    assert event.policy_version == 1
    assert event.execution_status == ExecutionStatus.NOT_EXECUTED.value
    assert event.verification_status == VerificationStatus.VERIFIED.value


@pytest.mark.asyncio
async def test_gateway_unauthorized_requests_create_audit_events(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    # Unauthenticated request with valid JSON still audits & rejects with 401
    resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Correlation-ID": "corr-unauth-001"},
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "documents/secret.txt",
        },
    )
    assert resp.status_code == 401

    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.correlation_id == "corr-unauth-001")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].agent_id is None
    assert events[0].decision == PolicyDecision.DENY.value
    assert events[0].verification_status == VerificationStatus.UNAUTHENTICATED.value
    assert events[0].tool_name == "file_reader"
    assert events[0].execution_status == ExecutionStatus.NOT_EXECUTED.value


@pytest.mark.asyncio
async def test_gateway_correlation_id_validation_and_generation(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    _, raw_key = await _bootstrap_agent_and_tool(client, admin_headers)

    # Generated UUID when omitted
    resp_auto = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key},
        json={"tool_name": "file_reader", "action": "read", "resource": "documents/a.txt"},
    )
    assert resp_auto.status_code == 200
    generated_cid = resp_auto.json()["correlation_id"]
    assert UUID(generated_cid)
    assert resp_auto.headers["X-Correlation-ID"] == generated_cid

    # Rejects malicious newline/invalid correlation IDs
    resp_bad = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key, "X-Correlation-ID": "bad id with spaces!"},
        json={"tool_name": "file_reader", "action": "read", "resource": "documents/a.txt"},
    )
    assert resp_bad.status_code == 400
    assert resp_bad.json()["error"]["code"] == "INVALID_CORRELATION_ID"


@pytest.mark.asyncio
async def test_audit_failure_fails_closed_never_returning_allow(
    client: AsyncClient,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, raw_key = await _bootstrap_agent_and_tool(client, admin_headers)
    await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "allow-all-docs",
            "agent_id": agent_id,
            "tool_name": "file_reader",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
        },
    )

    async def broken_record_event(*args, **kwargs):
        from app.core.exceptions import AuditPersistenceError

        raise AuditPersistenceError()

    monkeypatch.setattr(AuditService, "record_event", broken_record_event)

    resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key},
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"path": "documents/invoice.txt"},
        },
    )
    assert resp.status_code == 500
    assert resp.json()["error"]["code"] == "AUDIT_PERSISTENCE_ERROR"


@pytest.mark.asyncio
async def test_health_readiness_security_headers_and_rate_limit(
    test_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    settings = Settings(
        env="test",
        log_json=False,
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'unused.db').as_posix()}",
        admin_api_key="axly_adm_test_admin_key_0123456789abcdef_secure",
        api_key_hash_iterations=10_000,
        rate_limit_enabled=True,
        rate_limit_requests=2,
        rate_limit_window_seconds=60,
    )
    app = create_app(settings=settings, engine=test_engine)
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as limited_client:
            health = await limited_client.get("/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"
            assert health.headers["X-Content-Type-Options"] == "nosniff"
            assert health.headers["X-Frame-Options"] == "DENY"

            ready = await limited_client.get("/ready")
            assert ready.status_code == 200
            assert ready.json()["database"] == "connected"

            admin_hdr = {"X-Admin-Key": "axly_adm_test_admin_key_0123456789abcdef_secure"}
            # Rate limiter triggers 429 after 2 requests on API endpoints
            r1 = await limited_client.get("/api/v1/tools", headers=admin_hdr)
            r2 = await limited_client.get("/api/v1/tools", headers=admin_hdr)
            r3 = await limited_client.get("/api/v1/tools", headers=admin_hdr)
            assert r1.status_code == 200
            assert r2.status_code == 200
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers


@pytest.mark.asyncio
async def test_gateway_require_approval_disabled_tool_traversal_and_ready_503(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id, raw_key = await _bootstrap_agent_and_tool(client, admin_headers)

    # Approval-required policy
    p_resp = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "approve-contracts",
            "agent_id": agent_id,
            "tool_name": "file_reader",
            "action": "read",
            "resource_scope": "contracts/*",
            "decision": "require_approval",
            "priority": 100,
        },
    )
    assert p_resp.status_code == 201

    approval_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key, "X-Correlation-ID": "corr-approval-001"},
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "contracts/msa.pdf",
            "arguments": {"path": "contracts/msa.pdf"},
        },
    )
    assert approval_resp.status_code == 200
    assert approval_resp.json()["decision"] == "REQUIRE_APPROVAL"
    assert approval_resp.json()["execution_status"] == "not_executed"

    # Path traversal over HTTP is denied and audited
    traversal_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key, "X-Correlation-ID": "corr-traversal-001"},
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "contracts/../secrets.txt",
        },
    )
    assert traversal_resp.status_code == 200
    assert traversal_resp.json()["decision"] == "DENY"

    # Disable tool -> previously-matching policy must now return DENY
    disable_tool = await client.patch(
        "/api/v1/tools/file_reader",
        headers=admin_headers,
        json={"enabled": False},
    )
    assert disable_tool.status_code == 200
    disabled_eval = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key, "X-Correlation-ID": "corr-disabled-tool"},
        json={
            "tool_name": "file_reader",
            "action": "read",
            "resource": "contracts/msa.pdf",
        },
    )
    assert disabled_eval.status_code == 200
    assert disabled_eval.json()["decision"] == "DENY"

    # Audit events exist for all three evaluations
    audit_list = await client.get("/api/v1/audit-events", headers=admin_headers)
    assert audit_list.status_code == 200
    cids = {item["correlation_id"] for item in audit_list.json()["items"]}
    assert {"corr-approval-001", "corr-traversal-001", "corr-disabled-tool"} <= cids

    # Readiness returns 503 when DB check fails
    async def db_down(_session):
        raise RuntimeError("DB unreachable")

    monkeypatch.setattr("app.api.routes.health.check_database_connectivity", db_down)
    ready_down = await client.get("/ready")
    assert ready_down.status_code == 503
    assert ready_down.json()["database"] == "unavailable"

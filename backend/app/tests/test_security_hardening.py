"""Phase 4 security regression tests covering hardening, concurrency, and tamper detection."""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.adapters.base import AdapterSecurityError
from app.adapters.email_adapter import EmailToolAdapter
from app.adapters.file_adapter import resolve_sandbox_target
from app.approvals.models import ApprovalRequest
from app.core.config import Settings
from app.core.database import build_session_factory
from app.core.exceptions import AuditPersistenceError
from app.core.logging import redact_secrets
from app.main import create_app
from app.middleware.rate_limit import InMemorySlidingWindowLimiter
from app.models.audit import AuditEvent
from app.models.enums import AuditEventType, ExecutionStatus, PolicyDecision, VerificationStatus
from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_request_size_limit_production_docs_disabled_and_hardened_headers(
    test_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    prod_settings = Settings(
        env="production",
        log_json=True,
        database_url="postgresql+asyncpg://postgres:StrongPass123!@localhost:5432/chaperone",
        admin_api_key=SecretStr("axly_adm_production_test_key_0123456789abcdef_extra"),
        api_key_hash_iterations=10_000,
        rate_limit_enabled=False,
        max_request_body_bytes=4096,
        sandbox_dir=str(tmp_path / "sandbox"),
    )
    app = create_app(settings=prod_settings, engine=test_engine)
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://prodserver",
        ) as prod_client:
            # Swagger / OpenAPI disabled in production
            assert (await prod_client.get("/docs")).status_code == 404
            assert (await prod_client.get("/openapi.json")).status_code == 404

            health = await prod_client.get("/health")
            assert health.status_code == 200
            assert health.headers["Content-Security-Policy"] == (
                "default-src 'none'; frame-ancestors 'none'"
            )
            assert health.headers["X-Permitted-Cross-Domain-Policies"] == "none"
            assert "geolocation=()" in health.headers["Permissions-Policy"]

            # Oversized body rejected with 413 before parsing
            oversized = {"name": "a" * 5000}
            resp = await prod_client.post(
                "/api/v1/agents",
                headers={"X-Admin-Key": "axly_adm_production_test_key_0123456789abcdef_extra"},
                json=oversized,
            )
            assert resp.status_code == 413
            assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_rate_limiter_bounded_bucket_eviction() -> None:
    limiter = InMemorySlidingWindowLimiter(max_requests=2, window_seconds=60, max_buckets=5)
    for i in range(25):
        allowed, _ = limiter.check_and_consume(f"attacker_key_{i}")
        assert allowed is True
    assert len(limiter._buckets) <= 5


def test_secret_redaction_covers_dsn_bearer_and_validation_echo() -> None:
    raw = (
        "Failed connecting postgresql+asyncpg://chaperone:SuperSecret99@db.internal:5432/chaperone "
        "with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig and axly_adm_secretvalue123"
    )
    cleaned = redact_secrets(raw)
    assert "SuperSecret99" not in cleaned
    assert "eyJhbGciOiJIUzI1NiJ9" not in cleaned
    assert "axly_adm_secretvalue123" not in cleaned
    assert "[REDACTED]" in cleaned


@pytest.mark.asyncio
async def test_resource_smuggling_ads_reserved_names_bidi_junction_and_db_bool_overflow(
    client: AsyncClient,
    admin_headers: dict[str, str],
    test_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ag_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "hardening-agent"},
    )
    agent_id = ag_resp.json()["id"]
    agent_key = ag_resp.json()["api_key"]

    for name, cat in (
        ("file_tool", "filesystem"),
        ("email_tool", "communication"),
        ("database_tool", "database"),
    ):
        await client.post(
            "/api/v1/tools",
            headers=admin_headers,
            json={
                "name": name,
                "description": f"Controlled {name}",
                "category": cat,
                "risk_level": "medium",
            },
        )
        await client.post(
            "/api/v1/policies",
            headers=admin_headers,
            json={
                "name": f"allow-{name}",
                "agent_id": agent_id,
                "tool_name": name,
                "action": "*",
                "resource_scope": "*",
                "decision": "allow",
                "priority": 100,
            },
        )

    # 1. ADS colon, Windows reserved device names, and bidi override rejected
    for bad_path in (
        "documents/invoice.txt:hidden",
        "documents/CON.txt",
        "documents/NUL",
        "documents/invoice\u202etxt",
    ):
        resp = await client.post(
            "/api/v1/gateway/evaluate",
            headers={"X-Agent-Key": agent_key},
            json={"tool_name": "file_tool", "action": "read", "resource": bad_path},
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"

    # 2. Case-variant smuggling rejected across filesystem, email, and database
    case_smuggle_file = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "file_tool",
            "action": "read",
            "resource": "documents/invoice.txt",
            "arguments": {"Path": "private/secrets.txt"},
        },
    )
    assert case_smuggle_file.json()["decision"] == "DENY"

    case_smuggle_email = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "email_tool",
            "action": "send",
            "resource": "finance@company.com",
            "arguments": {"to": "finance@company.com", "BCC": ["evil@attacker.com"]},
        },
    )
    assert case_smuggle_email.json()["decision"] == "DENY"

    case_smuggle_sql = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "read",
            "resource": "demo_invoices",
            "arguments": {"SQL": "SELECT * FROM agents"},
        },
    )
    assert case_smuggle_sql.json()["decision"] == "DENY"

    # 3. DatabaseToolAdapter rejects bool-as-int and oversized integers safely
    bool_db = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "create",
            "resource": "demo_invoices",
            "arguments": {
                "table": "demo_invoices",
                "data": {
                    "invoice_number": "INV-BOOL-1",
                    "vendor_name": "Test",
                    "amount_inr": True,
                },
            },
        },
    )
    assert bool_db.status_code == 200
    assert bool_db.json()["status"] == "FAILED"

    overflow_db = await client.post(
        "/api/v1/gateway/execute",
        headers={"X-Agent-Key": agent_key},
        json={
            "tool_name": "database_tool",
            "action": "create",
            "resource": "demo_invoices",
            "arguments": {
                "table": "demo_invoices",
                "data": {
                    "invoice_number": "INV-BIG-1",
                    "vendor_name": "Test",
                    "amount_inr": 9_999_999_999_999,
                },
            },
        },
    )
    assert overflow_db.status_code == 200
    assert overflow_db.json()["status"] == "FAILED"

    # 4. NTFS Junction check blocks junction segments even when islink returns False
    sandbox_root = Path(test_settings.sandbox_dir)
    junction_dir = sandbox_root / "documents" / "junction_escape"
    if hasattr(os.path, "isjunction"):
        original_isjunction = os.path.isjunction
        monkeypatch.setattr(
            os.path,
            "isjunction",
            lambda p: True if Path(p) == junction_dir else original_isjunction(p),
        )
        with pytest.raises(AdapterSecurityError):
            resolve_sandbox_target(sandbox_root, "documents/junction_escape/secret.txt")


@pytest.mark.asyncio
async def test_audit_orm_immutability_and_hash_tamper_detection(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    svc = AuditService()
    created = await svc.record_event(
        db_session,
        correlation_id="corr-integrity-001",
        agent_id=None,
        tool_name="file_tool",
        action="read",
        resource="documents/invoice.txt",
        decision=PolicyDecision.ALLOW,
        reason="Valid read",
        policy_id=None,
        policy_version=None,
        policy_metadata=None,
        execution_status=ExecutionStatus.EXECUTED,
        verification_status=VerificationStatus.VERIFIED,
        event_type=AuditEventType.EXECUTION_COMPLETED,
    )
    assert created.record_hash is not None

    # Integrity check API confirms clean state
    ok_resp = await client.get("/api/v1/audit-events/integrity", headers=admin_headers)
    assert ok_resp.status_code == 200
    assert ok_resp.json()["intact"] is True
    assert ok_resp.json()["verified"] >= 1

    # ORM update / delete listeners block mutation
    created.reason = "Tampered at ORM layer"
    with pytest.raises(AuditPersistenceError):
        await db_session.commit()
    await db_session.rollback()

    await db_session.delete(created)
    with pytest.raises(AuditPersistenceError):
        await db_session.commit()
    await db_session.rollback()

    # Raw SQL tampering (simulating compromised DB credential) is detected by verify_integrity
    await db_session.execute(
        text("UPDATE audit_events SET reason = 'FORGED REASON' WHERE id = :eid"),
        {"eid": created.id.hex},
    )
    await db_session.commit()

    tamper_resp = await client.get("/api/v1/audit-events/integrity", headers=admin_headers)
    assert tamper_resp.status_code == 200
    assert tamper_resp.json()["intact"] is False
    assert tamper_resp.json()["tampered"] == 1
    assert str(created.id) in tamper_resp.json()["tampered_ids"]


@pytest.mark.asyncio
async def test_concurrent_approval_race_condition_executes_strictly_once(
    test_engine: AsyncEngine,
    test_settings: Settings,
    admin_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(settings=test_settings, engine=test_engine)
    session_factory = build_session_factory(test_engine)
    exec_calls = 0
    real_email_exec = EmailToolAdapter.execute

    async def counted_email_exec(self: EmailToolAdapter, context):
        nonlocal exec_calls
        exec_calls += 1
        return await real_email_exec(self, context)

    monkeypatch.setattr(EmailToolAdapter, "execute", counted_email_exec)

    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://raceserver",
        ) as race_client:
            ag = (
                await race_client.post(
                    "/api/v1/agents", headers=admin_headers, json={"name": "race-agent"}
                )
            ).json()
            await race_client.post(
                "/api/v1/tools",
                headers=admin_headers,
                json={
                    "name": "email_tool",
                    "description": "Mock email",
                    "category": "communication",
                    "risk_level": "high",
                },
            )
            await race_client.post(
                "/api/v1/policies",
                headers=admin_headers,
                json={
                    "name": "approve-race-email",
                    "agent_id": ag["id"],
                    "tool_name": "email_tool",
                    "action": "send",
                    "resource_scope": "*@company.com",
                    "decision": "require_approval",
                },
            )
            pending = (
                await race_client.post(
                    "/api/v1/gateway/execute",
                    headers={"X-Agent-Key": ag["api_key"]},
                    json={
                        "tool_name": "email_tool",
                        "action": "send",
                        "resource": "cfo@company.com",
                        "arguments": {
                            "to": "cfo@company.com",
                            "subject": "Concurrency Check",
                            "body": "Must run once",
                        },
                    },
                )
            ).json()
            ap_id = pending["approval_id"]

            # Approve 2-step first, then fire two concurrent executions via gateway
            await race_client.post(
                f"/api/v1/approvals/{ap_id}/approve",
                headers=admin_headers,
                json={"execute_now": False},
            )

            async def _fire() -> int:
                res = await race_client.post(
                    "/api/v1/gateway/execute",
                    headers={"X-Agent-Key": ag["api_key"]},
                    json={
                        "tool_name": "email_tool",
                        "action": "send",
                        "resource": "cfo@company.com",
                        "arguments": {
                            "to": "cfo@company.com",
                            "subject": "Concurrency Check",
                            "body": "Must run once",
                        },
                        "approval_id": ap_id,
                    },
                )
                return res.status_code

            statuses = await asyncio.gather(_fire(), _fire())
            assert sorted(statuses) == [200, 409]
            assert exec_calls == 1

            # Also verify expiration of an APPROVED request creates APPROVAL_EXPIRED audit event
            pending2 = (
                await race_client.post(
                    "/api/v1/gateway/execute",
                    headers={"X-Agent-Key": ag["api_key"]},
                    json={
                        "tool_name": "email_tool",
                        "action": "send",
                        "resource": "ops@company.com",
                        "arguments": {"to": "ops@company.com", "subject": "Late", "body": "Test"},
                    },
                )
            ).json()
            ap2_id = pending2["approval_id"]
            await race_client.post(
                f"/api/v1/approvals/{ap2_id}/approve",
                headers=admin_headers,
                json={"execute_now": False},
            )
            async with session_factory() as s:
                await s.execute(
                    update(ApprovalRequest)
                    .where(ApprovalRequest.id == UUID(ap2_id))
                    .values(expires_at=datetime.now(UTC) - timedelta(seconds=60))
                )
                await s.commit()

            expired_exec = await race_client.post(
                "/api/v1/gateway/execute",
                headers={"X-Agent-Key": ag["api_key"]},
                json={
                    "tool_name": "email_tool",
                    "action": "send",
                    "resource": "ops@company.com",
                    "arguments": {"to": "ops@company.com", "subject": "Late", "body": "Test"},
                    "approval_id": ap2_id,
                },
            )
            assert expired_exec.status_code == 409
            assert expired_exec.json()["error"]["code"] == "APPROVAL_EXPIRED"

            async with session_factory() as s:
                from sqlalchemy import select

                ev = (
                    await s.execute(
                        select(AuditEvent).where(
                            AuditEvent.approval_id == UUID(ap2_id),
                            AuditEvent.event_type == AuditEventType.APPROVAL_EXPIRED.value,
                        )
                    )
                ).scalar_one_or_none()
                assert ev is not None

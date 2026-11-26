"""Tests for agent authentication, admin separation, and one-time API key security."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings
from app.main import create_app


@pytest.mark.asyncio
async def test_agent_registration_returns_key_once_and_never_exposes_hash(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    create_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "billing-agent", "description": "Reads approved invoices"},
    )
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["api_key"].startswith("axly_ag_")
    assert "api_key_hash" not in created
    agent_id = created["id"]

    # List endpoint must never return raw api_key or api_key_hash
    list_resp = await client.get("/api/v1/agents", headers=admin_headers)
    assert list_resp.status_code == 200
    listed = list_resp.json()
    assert listed["total"] == 1
    item = listed["items"][0]
    assert "api_key" not in item
    assert "api_key_hash" not in item
    assert item["key_prefix"].startswith("axly_ag_")

    # Detail endpoint must never return raw api_key or api_key_hash
    detail_resp = await client.get(f"/api/v1/agents/{agent_id}", headers=admin_headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert "api_key" not in detail
    assert "api_key_hash" not in detail


@pytest.mark.asyncio
async def test_agent_authentication_valid_invalid_missing_and_disabled(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    # Setup tool & agent
    tool_resp = await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "file_reader",
            "description": "Reads workspace files",
            "category": "filesystem",
            "risk_level": "low",
        },
    )
    assert tool_resp.status_code == 201

    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "auth-test-agent"},
    )
    assert agent_resp.status_code == 201
    agent_data = agent_resp.json()
    agent_id = agent_data["id"]
    raw_key = agent_data["api_key"]

    payload = {
        "tool_name": "file_reader",
        "action": "read",
        "resource": "documents/invoice.txt",
        "arguments": {"path": "documents/invoice.txt"},
    }

    # 1. Missing API key -> 401
    missing_resp = await client.post("/api/v1/gateway/evaluate", json=payload)
    assert missing_resp.status_code == 401

    # 2. Invalid API key (wrong secret, matching format) -> 401
    tampered_key = f"{raw_key[:-4]}ZZZZ"
    invalid_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": tampered_key},
        json=payload,
    )
    assert invalid_resp.status_code == 401

    # 3. Malformed API key -> 401
    malformed_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": "not-a-valid-key"},
        json=payload,
    )
    assert malformed_resp.status_code == 401

    # 4. Valid API key -> 200 (default deny because no allow policy yet)
    valid_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key},
        json=payload,
    )
    assert valid_resp.status_code == 200
    assert valid_resp.json()["decision"] == "DENY"

    # 5. Disable agent -> 403
    disable_resp = await client.patch(
        f"/api/v1/agents/{agent_id}/status",
        headers=admin_headers,
        json={"status": "disabled"},
    )
    assert disable_resp.status_code == 200
    assert disable_resp.json()["status"] == "disabled"

    disabled_gateway_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key},
        json=payload,
    )
    assert disabled_gateway_resp.status_code == 403
    assert disabled_gateway_resp.json()["error"]["code"] == "AGENT_DISABLED"

    # 6. Re-enable agent -> 200 again
    enable_resp = await client.patch(
        f"/api/v1/agents/{agent_id}/status",
        headers=admin_headers,
        json={"status": "active"},
    )
    assert enable_resp.status_code == 200
    reenabled_resp = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": raw_key},
        json=payload,
    )
    assert reenabled_resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_and_agent_credential_separation(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    agent_resp = await client.post(
        "/api/v1/agents",
        headers=admin_headers,
        json={"name": "non-admin-agent"},
    )
    raw_key = agent_resp.json()["api_key"]

    # Unauthenticated access to admin endpoints is rejected
    assert (await client.get("/api/v1/agents")).status_code == 401
    assert (await client.get("/api/v1/tools")).status_code == 401
    assert (await client.get("/api/v1/policies")).status_code == 401
    assert (await client.get("/api/v1/audit-events")).status_code == 401

    # Agent key cannot access admin endpoints
    assert (await client.get("/api/v1/agents", headers={"X-Admin-Key": raw_key})).status_code == 401
    assert (
        await client.post(
            "/api/v1/tools",
            headers={"X-Agent-Key": raw_key},
            json={
                "name": "rogue_tool",
                "description": "Should fail",
                "category": "system",
                "risk_level": "critical",
            },
        )
    ).status_code == 401

    # Admin key cannot authenticate as an agent on gateway
    gateway_with_admin = await client.post(
        "/api/v1/gateway/evaluate",
        headers={"X-Agent-Key": admin_headers["X-Admin-Key"]},
        json={"tool_name": "file_reader", "action": "read", "resource": "documents/a.txt"},
    )
    assert gateway_with_admin.status_code == 401


@pytest.mark.asyncio
async def test_unconfigured_admin_key_fails_closed(
    test_engine: AsyncEngine,
    tmp_path: Path,
) -> None:
    settings_without_admin = Settings(
        env="development",
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'unused.db').as_posix()}",
        admin_api_key=None,
        rate_limit_enabled=False,
    )
    app = create_app(settings=settings_without_admin, engine=test_engine)
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as unconfigured_client:
            resp = await unconfigured_client.get(
                "/api/v1/agents",
                headers={"X-Admin-Key": "anything"},
            )
            assert resp.status_code == 503
            assert resp.json()["error"]["code"] == "ADMIN_NOT_CONFIGURED"

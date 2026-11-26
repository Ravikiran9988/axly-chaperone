"""Integration tests for Tool Registry, Policy CRUD, Audit append-only API, and secret redaction."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.logging import redact_secrets


@pytest.mark.asyncio
async def test_tool_registry_and_policy_versioning(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    # Register tool
    t_resp = await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "email_sender",
            "description": "Sends outbound email messages",
            "category": "communication",
            "risk_level": "high",
            "enabled": True,
        },
    )
    assert t_resp.status_code == 201
    assert t_resp.json()["risk_level"] == "high"

    # Duplicate tool rejected
    dup_resp = await client.post(
        "/api/v1/tools",
        headers=admin_headers,
        json={
            "name": "email_sender",
            "description": "Dup",
            "category": "communication",
            "risk_level": "high",
        },
    )
    assert dup_resp.status_code == 409

    # Policy referencing unregistered tool fails with 404
    bad_policy = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "ghost-policy",
            "tool_name": "nonexistent_tool",
            "action": "run",
            "resource_scope": "*",
            "decision": "allow",
        },
    )
    assert bad_policy.status_code == 404

    # Create valid policy and verify version increments on PATCH
    p_resp = await client.post(
        "/api/v1/policies",
        headers=admin_headers,
        json={
            "name": "approve-external-email",
            "tool_name": "email_sender",
            "action": "send",
            "resource_scope": "*@company.com",
            "decision": "require_approval",
            "priority": 150,
        },
    )
    assert p_resp.status_code == 201
    policy_id = p_resp.json()["id"]
    assert p_resp.json()["version"] == 1

    patch_resp = await client.patch(
        f"/api/v1/policies/{policy_id}",
        headers=admin_headers,
        json={"priority": 250},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["version"] == 2
    assert patch_resp.json()["priority"] == 250


@pytest.mark.asyncio
async def test_audit_events_are_append_only_through_api(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    list_resp = await client.get("/api/v1/audit-events", headers=admin_headers)
    assert list_resp.status_code == 200

    # Mutating HTTP methods must not be exposed on audit events
    post_resp = await client.post("/api/v1/audit-events", headers=admin_headers, json={})
    assert post_resp.status_code == 405

    delete_resp = await client.delete(
        "/api/v1/audit-events/00000000-0000-0000-0000-000000000000",
        headers=admin_headers,
    )
    assert delete_resp.status_code == 405

    patch_resp = await client.patch(
        "/api/v1/audit-events/00000000-0000-0000-0000-000000000000",
        headers=admin_headers,
        json={},
    )
    assert patch_resp.status_code == 405


def test_secret_redaction_strips_api_keys_and_hashes() -> None:
    msg = (
        "Failed auth with X-Agent-Key: axly_ag_0123456789abcdef_secretsecret1234567890 "
        "and hash pbkdf2_sha256$200000$c2FsdA==$ZGlnZXN0"
    )
    cleaned = redact_secrets(msg)
    assert "axly_ag_" not in cleaned
    assert "secretsecret" not in cleaned
    assert "pbkdf2_sha256$" not in cleaned
    assert "[REDACTED]" in cleaned

"""Comprehensive unit tests for deterministic policy evaluation and resource validation."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from app.models.enums import AgentStatus, PolicyDecision, VerificationStatus
from app.security.policy_engine import (
    AgentContext,
    EvaluationRequest,
    PolicyEngine,
    PolicyRule,
    ToolContext,
)
from app.security.resource_validator import validate_resource_scope


def _make_policy(
    *,
    name: str,
    decision: PolicyDecision,
    priority: int = 100,
    agent_id: UUID | None = None,
    tool_name: str = "file_reader",
    action: str = "read",
    resource_scope: str = "documents/*",
    enabled: bool = True,
    version: int = 1,
) -> PolicyRule:
    return PolicyRule(
        id=uuid4(),
        name=name,
        agent_id=agent_id,
        tool_name=tool_name,
        action=action,
        resource_scope=resource_scope,
        decision=decision,
        enabled=enabled,
        priority=priority,
        version=version,
    )


def _eval(
    *,
    agent_id: UUID | None = None,
    agent_status: AgentStatus = AgentStatus.ACTIVE,
    authenticated: bool = True,
    tool_name: str = "file_reader",
    tool_category: str = "filesystem",
    tool_exists: bool = True,
    tool_enabled: bool = True,
    action: str = "read",
    resource: str = "documents/invoice.txt",
    arguments: dict | None = None,
    policies: list[PolicyRule] | None = None,
):
    resolved_agent_id = agent_id or uuid4()
    engine = PolicyEngine()
    return engine.evaluate(
        agent=AgentContext(
            id=resolved_agent_id if authenticated or agent_id is not None else None,
            status=agent_status,
            authenticated=authenticated,
        ),
        tool=ToolContext(
            name=tool_name,
            category=tool_category,
            exists=tool_exists,
            enabled=tool_enabled,
        ),
        request=EvaluationRequest(
            tool_name=tool_name,
            action=action,
            resource=resource,
            arguments=arguments,
            correlation_id="corr-unit-001",
        ),
        policies=policies or [],
    )


def test_default_deny_when_no_policy_matches() -> None:
    res = _eval(policies=[])
    assert res.decision == PolicyDecision.DENY
    assert res.reason == "No matching permission policy"
    assert res.matched_policy_id is None
    assert res.verification_status == VerificationStatus.VERIFIED


def test_allow_deny_and_require_approval_decisions() -> None:
    agent_id = uuid4()
    allow_policy = _make_policy(
        name="allow-docs",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
    )
    res_allow = _eval(agent_id=agent_id, policies=[allow_policy])
    assert res_allow.decision == PolicyDecision.ALLOW
    assert res_allow.matched_policy_id == allow_policy.id

    deny_policy = _make_policy(
        name="deny-docs",
        decision=PolicyDecision.DENY,
        agent_id=agent_id,
    )
    res_deny = _eval(agent_id=agent_id, policies=[deny_policy])
    assert res_deny.decision == PolicyDecision.DENY
    assert res_deny.matched_policy_id == deny_policy.id

    approval_policy = _make_policy(
        name="approve-docs",
        decision=PolicyDecision.REQUIRE_APPROVAL,
        agent_id=agent_id,
    )
    res_approval = _eval(agent_id=agent_id, policies=[approval_policy])
    assert res_approval.decision == PolicyDecision.REQUIRE_APPROVAL
    assert res_approval.matched_policy_id == approval_policy.id


def test_disabled_tool_and_disabled_agent_always_denied() -> None:
    agent_id = uuid4()
    allow_all = _make_policy(
        name="allow-all",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        resource_scope="*",
    )

    res_disabled_tool = _eval(agent_id=agent_id, tool_enabled=False, policies=[allow_all])
    assert res_disabled_tool.decision == PolicyDecision.DENY
    assert res_disabled_tool.verification_status == VerificationStatus.TOOL_UNAVAILABLE
    assert res_disabled_tool.matched_policy_id is None

    res_unknown_tool = _eval(agent_id=agent_id, tool_exists=False, policies=[allow_all])
    assert res_unknown_tool.decision == PolicyDecision.DENY
    assert res_unknown_tool.verification_status == VerificationStatus.TOOL_UNAVAILABLE

    res_disabled_agent = _eval(
        agent_id=agent_id,
        agent_status=AgentStatus.DISABLED,
        policies=[allow_all],
    )
    assert res_disabled_agent.decision == PolicyDecision.DENY
    assert res_disabled_agent.verification_status == VerificationStatus.AGENT_DISABLED


def test_conflicting_policies_precedence_rules() -> None:
    agent_id = uuid4()

    # 1. Higher-priority DENY overrides lower-priority ALLOW
    low_allow = _make_policy(
        name="allow-docs",
        decision=PolicyDecision.ALLOW,
        priority=100,
        agent_id=agent_id,
    )
    high_deny = _make_policy(
        name="deny-secrets",
        decision=PolicyDecision.DENY,
        priority=200,
        agent_id=agent_id,
        resource_scope="documents/secrets/*",
    )
    res1 = _eval(
        agent_id=agent_id,
        resource="documents/secrets/keys.txt",
        policies=[low_allow, high_deny],
    )
    assert res1.decision == PolicyDecision.DENY
    assert res1.matched_policy_id == high_deny.id

    # 2. Explicit DENY cannot be bypassed by REQUIRE_APPROVAL (even at higher priority)
    low_deny = _make_policy(
        name="explicit-deny",
        decision=PolicyDecision.DENY,
        priority=50,
        agent_id=agent_id,
        resource_scope="documents/secrets/*",
    )
    high_approval = _make_policy(
        name="broad-approval",
        decision=PolicyDecision.REQUIRE_APPROVAL,
        priority=500,
        agent_id=agent_id,
        resource_scope="documents/*",
    )
    res2 = _eval(
        agent_id=agent_id,
        resource="documents/secrets/keys.txt",
        policies=[low_deny, high_approval],
    )
    assert res2.decision == PolicyDecision.DENY
    assert res2.matched_policy_id == low_deny.id

    # 3. Higher-priority ALLOW overrides lower-priority REQUIRE_APPROVAL
    low_approval = _make_policy(
        name="default-approval",
        decision=PolicyDecision.REQUIRE_APPROVAL,
        priority=100,
        agent_id=agent_id,
        resource_scope="documents/*",
    )
    high_allow = _make_policy(
        name="allow-public",
        decision=PolicyDecision.ALLOW,
        priority=200,
        agent_id=agent_id,
        resource_scope="documents/public/*",
    )
    res3 = _eval(
        agent_id=agent_id,
        resource="documents/public/readme.md",
        policies=[low_approval, high_allow],
    )
    assert res3.decision == PolicyDecision.ALLOW
    assert res3.matched_policy_id == high_allow.id

    # 4. Priority tie between ALLOW and REQUIRE_APPROVAL fails safe to REQUIRE_APPROVAL
    tied_allow = _make_policy(
        name="tied-allow",
        decision=PolicyDecision.ALLOW,
        priority=100,
        agent_id=agent_id,
    )
    tied_approval = _make_policy(
        name="tied-approval",
        decision=PolicyDecision.REQUIRE_APPROVAL,
        priority=100,
        agent_id=agent_id,
    )
    res4 = _eval(agent_id=agent_id, policies=[tied_allow, tied_approval])
    assert res4.decision == PolicyDecision.REQUIRE_APPROVAL
    assert res4.matched_policy_id == tied_approval.id


def test_resource_scope_mismatch_and_no_unsafe_substring_matching() -> None:
    agent_id = uuid4()
    docs_allow = _make_policy(
        name="allow-docs",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        resource_scope="documents/*",
    )

    # Prefix boundary must NOT match sibling directory starting with "documents"
    res_sibling = _eval(
        agent_id=agent_id,
        resource="documents_private/invoice.txt",
        policies=[docs_allow],
    )
    assert res_sibling.decision == PolicyDecision.DENY

    # Prefix wildcard must NOT match bare prefix without segment
    res_bare = _eval(agent_id=agent_id, resource="documents", policies=[docs_allow])
    assert res_bare.decision == PolicyDecision.DENY

    # Email domain scope must NOT match suffix-alike domains
    email_allow = _make_policy(
        name="allow-company-mail",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        tool_name="email_sender",
        action="send",
        resource_scope="*@company.com",
    )
    res_evil_email = _eval(
        agent_id=agent_id,
        tool_name="email_sender",
        tool_category="communication",
        action="send",
        resource="ceo@evilcompany.com",
        policies=[email_allow],
    )
    assert res_evil_email.decision == PolicyDecision.DENY

    # URL origin scope must NOT match lookalike hostnames
    url_allow = _make_policy(
        name="allow-api-origin",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        tool_name="http_client",
        action="get",
        resource_scope="https://api.example.com/*",
    )
    res_evil_url = _eval(
        agent_id=agent_id,
        tool_name="http_client",
        tool_category="network",
        action="get",
        resource="https://api.example.com.attacker.io/v1/users",
        policies=[url_allow],
    )
    assert res_evil_url.decision == PolicyDecision.DENY


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../secrets.txt",
        "documents/../secrets.txt",
        "documents/./invoice.txt",
        "documents//invoice.txt",
        "documents\\invoice.txt",
        "/etc/passwd",
        "C:\\Windows\\system.ini",
        "documents/%2e%2e/secrets.txt",
        "documents/invoice.txt\x00.pdf",
        " documents/invoice.txt",
    ],
)
def test_path_traversal_and_ambiguous_paths_always_denied(unsafe_path: str) -> None:
    agent_id = uuid4()
    allow_all = _make_policy(
        name="allow-everything",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        resource_scope="*",
    )
    res = _eval(agent_id=agent_id, resource=unsafe_path, policies=[allow_all])
    assert res.decision == PolicyDecision.DENY
    assert res.verification_status == VerificationStatus.VALIDATION_FAILED


def test_resource_argument_smuggling_rejected() -> None:
    agent_id = uuid4()
    allow_docs = _make_policy(
        name="allow-docs",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        resource_scope="documents/*",
    )
    res_mismatch = _eval(
        agent_id=agent_id,
        resource="documents/invoice.txt",
        arguments={"path": "secrets/master.key"},
        policies=[allow_docs],
    )
    assert res_mismatch.decision == PolicyDecision.DENY
    assert res_mismatch.verification_status == VerificationStatus.VALIDATION_FAILED

    # Nested argument smuggling rejected
    res_nested_mismatch = _eval(
        agent_id=agent_id,
        resource="documents/invoice.txt",
        arguments={"options": {"path": "secrets/master.key"}},
        policies=[allow_docs],
    )
    assert res_nested_mismatch.decision == PolicyDecision.DENY
    assert res_nested_mismatch.verification_status == VerificationStatus.VALIDATION_FAILED

    # Email multi-recipient smuggling rejected
    email_allow = _make_policy(
        name="allow-internal-email",
        decision=PolicyDecision.ALLOW,
        agent_id=agent_id,
        tool_name="email_sender",
        action="send",
        resource_scope="*@company.com",
    )
    res_email_smuggle = _eval(
        agent_id=agent_id,
        tool_name="email_sender",
        tool_category="communication",
        action="send",
        resource="ops@company.com",
        arguments={"to": ["ops@company.com", "exfil@attacker.com"]},
        policies=[email_allow],
    )
    assert res_email_smuggle.decision == PolicyDecision.DENY
    assert res_email_smuggle.verification_status == VerificationStatus.VALIDATION_FAILED


def test_validate_resource_scope_rejects_unsafe_patterns() -> None:
    assert validate_resource_scope("*") == "*"
    assert validate_resource_scope("documents/*") == "documents/*"
    assert validate_resource_scope("*@Example.COM") == "*@example.com"
    assert validate_resource_scope("https://API.Example.com/v1/*") == "https://api.example.com/v1/*"

    for bad_scope in ["*secret*", "doc*/file", "documents/**", "documents/../x", "?/foo"]:
        with pytest.raises(ValueError):
            validate_resource_scope(bad_scope)

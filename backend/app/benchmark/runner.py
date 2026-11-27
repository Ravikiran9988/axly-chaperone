"""Reproducible benchmark runner for security metrics, latency percentiles, and reports."""

from __future__ import annotations

import asyncio
import json
import math
import os
import platform
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from app.adapters.file_adapter import ensure_demo_sandbox
from app.adapters.mcp.client import connect_in_memory_mcp
from app.adapters.mcp.server import create_chaperone_mcp_server
from app.benchmark.scenarios import BenchmarkContext, ScenarioOutcome, run_all_scenarios
from app.core.config import Settings
from app.core.database import Base, build_engine, build_session_factory
from app.execution.dispatcher import ExecutionDispatcher
from app.main import create_app
from app.security.policy_engine import PolicyEngine


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, math.ceil((pct / 100.0) * len(ordered)) - 1)
    return round(ordered[rank], 3)


def _latency_summary(values: list[float]) -> dict[str, float | int]:
    if not values:
        return {"samples": 0, "p50_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0, "mean_ms": 0.0}
    return {
        "samples": len(values),
        "p50_ms": _percentile(values, 50.0),
        "p95_ms": _percentile(values, 95.0),
        "max_ms": round(max(values), 3),
        "mean_ms": round(sum(values) / len(values), 3),
    }


async def _seed_benchmark_entities(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> tuple[str, str, str, str, str, str]:
    # 1. Primary agent, secondary agent, and disabled agent
    ag1 = (
        await client.post(
            "/api/v1/agents",
            headers=admin_headers,
            json={"name": "bench-primary-agent", "description": "Benchmark primary agent"},
        )
    ).json()
    ag2 = (
        await client.post(
            "/api/v1/agents",
            headers=admin_headers,
            json={"name": "bench-secondary-agent", "description": "Benchmark secondary agent"},
        )
    ).json()
    ag3 = (
        await client.post(
            "/api/v1/agents",
            headers=admin_headers,
            json={"name": "bench-disabled-agent", "description": "Benchmark disabled agent"},
        )
    ).json()
    await client.patch(
        f"/api/v1/agents/{ag3['id']}/status",
        headers=admin_headers,
        json={"status": "disabled"},
    )

    # 2. Register tools
    for tool in (
        {
            "name": "file_tool",
            "description": "Controlled sandbox filesystem adapter",
            "category": "filesystem",
            "risk_level": "medium",
            "enabled": True,
        },
        {
            "name": "email_tool",
            "description": "Controlled mock email provider adapter",
            "category": "communication",
            "risk_level": "high",
            "enabled": True,
        },
        {
            "name": "database_tool",
            "description": "Controlled parameterized demo table adapter",
            "category": "database",
            "risk_level": "medium",
            "enabled": True,
        },
        {
            "name": "analytics_tool",
            "description": "Evaluation-only metadata tool",
            "category": "analytics",
            "risk_level": "low",
            "enabled": True,
        },
    ):
        resp = await client.post("/api/v1/tools", headers=admin_headers, json=tool)
        assert resp.status_code == 201, resp.text

    # 3. Deterministic policies for benchmark suite
    policies = [
        # Primary agent allowed file operations on documents/*
        {
            "name": "bench-primary-allow-docs",
            "agent_id": ag1["id"],
            "tool_name": "file_tool",
            "action": "*",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
        # Primary agent list documents directory
        {
            "name": "bench-primary-allow-list-docs",
            "agent_id": ag1["id"],
            "tool_name": "file_tool",
            "action": "list",
            "resource_scope": "documents",
            "decision": "allow",
            "priority": 100,
        },
        # Precedence test: tied priority 100 REQUIRE_APPROVAL on documents/sensitive/*
        {
            "name": "bench-sensitive-tie-approval",
            "agent_id": ag1["id"],
            "tool_name": "file_tool",
            "action": "write",
            "resource_scope": "documents/sensitive/*",
            "decision": "require_approval",
            "priority": 100,
        },
        # Precedence test: lower REQUIRE_APPROVAL overridden by higher ALLOW on documents/public/*
        {
            "name": "bench-public-higher-allow",
            "agent_id": ag1["id"],
            "tool_name": "file_tool",
            "action": "write",
            "resource_scope": "documents/public/*",
            "decision": "allow",
            "priority": 250,
        },
        # Explicit global DENY on private/* (highest security guarantee)
        {
            "name": "bench-global-deny-private",
            "agent_id": None,
            "tool_name": "file_tool",
            "action": "*",
            "resource_scope": "private/*",
            "decision": "deny",
            "priority": 500,
        },
        # Secondary agent allowed only project_notes.txt
        {
            "name": "bench-secondary-allow-notes",
            "agent_id": ag2["id"],
            "tool_name": "file_tool",
            "action": "read",
            "resource_scope": "documents/project_notes.txt",
            "decision": "allow",
            "priority": 100,
        },
        # Email policies: drafts & reads allowed internally, sends require approval, attacker denied
        {
            "name": "bench-primary-allow-drafts",
            "agent_id": ag1["id"],
            "tool_name": "email_tool",
            "action": "create_draft",
            "resource_scope": "*@company.com",
            "decision": "allow",
            "priority": 100,
        },
        {
            "name": "bench-primary-allow-email-read",
            "agent_id": ag1["id"],
            "tool_name": "email_tool",
            "action": "read",
            "resource_scope": "drafts",
            "decision": "allow",
            "priority": 100,
        },
        {
            "name": "bench-primary-require-approval-send",
            "agent_id": ag1["id"],
            "tool_name": "email_tool",
            "action": "send",
            "resource_scope": "*@company.com",
            "decision": "require_approval",
            "priority": 100,
        },
        {
            "name": "bench-global-deny-attacker-email",
            "agent_id": None,
            "tool_name": "email_tool",
            "action": "*",
            "resource_scope": "attacker@example.com",
            "decision": "deny",
            "priority": 500,
        },
        # Database policies on demo_invoices & demo_tasks only
        {
            "name": "bench-primary-allow-demo-invoices",
            "agent_id": ag1["id"],
            "tool_name": "database_tool",
            "action": "*",
            "resource_scope": "demo_invoices",
            "decision": "allow",
            "priority": 100,
        },
        {
            "name": "bench-primary-allow-demo-tasks",
            "agent_id": ag1["id"],
            "tool_name": "database_tool",
            "action": "*",
            "resource_scope": "demo_tasks",
            "decision": "allow",
            "priority": 100,
        },
        # Evaluation-only tool policy
        {
            "name": "bench-primary-allow-analytics",
            "agent_id": ag1["id"],
            "tool_name": "analytics_tool",
            "action": "query",
            "resource_scope": "metrics/*",
            "decision": "allow",
            "priority": 100,
        },
        # Disabled agent still has a policy — disabled status gate MUST override
        {
            "name": "bench-disabled-agent-policy",
            "agent_id": ag3["id"],
            "tool_name": "file_tool",
            "action": "read",
            "resource_scope": "documents/*",
            "decision": "allow",
            "priority": 100,
        },
    ]
    for pol in policies:
        resp = await client.post("/api/v1/policies", headers=admin_headers, json=pol)
        assert resp.status_code == 201, resp.text

    return (
        ag1["id"],
        ag1["api_key"],
        ag2["id"],
        ag2["api_key"],
        ag3["id"],
        ag3["api_key"],
    )


def _compute_metrics(outcomes: list[ScenarioOutcome]) -> dict[str, Any]:
    malicious = [o for o in outcomes if o.classification == "malicious"]
    legitimate = [o for o in outcomes if o.classification == "legitimate"]

    # Unauthorized action prevented = malicious scenario passed & was not executed
    prevented_malicious = sum(1 for o in malicious if o.passed)
    legit_succeeded = sum(1 for o in legitimate if o.passed)
    false_blocks = sum(
        1
        for o in legitimate
        if o.actual_decision in {"DENY", "AUTH_REJECTED", "AGENT_DISABLED"}
        or o.actual_execution_behavior == "blocked_before_execution"
    )

    policy_cases = [o for o in outcomes if o.is_policy_case]
    correct_policy = sum(1 for o in policy_cases if o.actual_decision == o.expected_decision)

    verif_cases = [
        o for o in outcomes if o.is_verification_case and o.verification_correct is not None
    ]
    correct_verif = sum(1 for o in verif_cases if o.verification_correct)

    total = len(outcomes)
    passed = sum(1 for o in outcomes if o.passed)
    failed = total - passed

    gateway_latencies = [o.gateway_latency_ms for o in outcomes if o.gateway_latency_ms > 0]
    policy_latencies = [o.policy_eval_latency_ms for o in outcomes if o.policy_eval_latency_ms > 0]
    tool_latencies = [o.tool_exec_latency_ms for o in outcomes if o.tool_exec_latency_ms > 0]
    overhead_latencies = [
        round(max(0.0, o.gateway_latency_ms - o.tool_exec_latency_ms), 3)
        for o in outcomes
        if o.gateway_latency_ms > 0
    ]

    return {
        "counts": {
            "total_scenarios": total,
            "malicious_scenarios": len(malicious),
            "legitimate_scenarios": len(legitimate),
            "passed_scenarios": passed,
            "failed_scenarios": failed,
            "skipped_scenarios": 0,
        },
        "rates": {
            "security_blocking_rate": round(prevented_malicious / len(malicious), 4)
            if malicious
            else 0.0,
            "legitimate_task_success_rate": round(legit_succeeded / len(legitimate), 4)
            if legitimate
            else 0.0,
            "false_block_rate": round(false_blocks / len(legitimate), 4) if legitimate else 0.0,
            "policy_decision_accuracy": round(correct_policy / len(policy_cases), 4)
            if policy_cases
            else 0.0,
            "outcome_verification_accuracy": round(correct_verif / len(verif_cases), 4)
            if verif_cases
            else 0.0,
        },
        "denominators": {
            "unauthorized_attempts": len(malicious),
            "unauthorized_prevented": prevented_malicious,
            "legitimate_attempts": len(legitimate),
            "legitimate_succeeded": legit_succeeded,
            "false_blocks": false_blocks,
            "policy_cases": len(policy_cases),
            "policy_correct": correct_policy,
            "verification_cases": len(verif_cases),
            "verification_correct": correct_verif,
        },
        "latency": {
            "gateway_total": _latency_summary(gateway_latencies),
            "gateway_overhead_excluding_tool": _latency_summary(overhead_latencies),
            "policy_engine_eval": _latency_summary(policy_latencies),
            "tool_adapter_execution": _latency_summary(tool_latencies),
        },
    }


def _render_markdown_report(report: dict[str, Any]) -> str:
    m = report["metrics"]
    c = m["counts"]
    r = m["rates"]
    d = m["denominators"]
    lat = m["latency"]
    env = report["environment"]

    lines = [
        "# AXLY Chaperone — Security Benchmark Report",
        "",
        f"- **Generated (UTC):** `{report['timestamp_utc']}`",
        (
            f"- **Platform:** `{env['platform']}` | **Python:** `{env['python_version']}`"
            f" | **CPU Cores:** `{env['cpu_count']}`"
        ),
        (
            f"- **Database Backend:** `{env['database_backend']}`"
            " | **Rate Limiter:** `disabled for benchmark throughput`"
        ),
        "",
        "## Summary Counts",
        "",
        "| Metric | Value |",
        "|---|---|",
        (
            f"| Total Scenarios | **{c['total_scenarios']}** "
            f"({c['malicious_scenarios']} malicious / {c['legitimate_scenarios']} legitimate) |"
        ),
        f"| Passed Scenarios | **{c['passed_scenarios']}** |",
        f"| Failed Scenarios | **{c['failed_scenarios']}** |",
        f"| Skipped Scenarios | **{c['skipped_scenarios']}** |",
        "",
        "## Security & Accuracy Metrics (Measured)",
        "",
        "| Metric | Rate | Exact Ratio |",
        "|---|---|---|",
        (
            f"| Security Blocking Rate | **{r['security_blocking_rate'] * 100:.2f}%** | "
            f"{d['unauthorized_prevented']} / {d['unauthorized_attempts']} |"
        ),
        (
            "| Legitimate Task Success Rate | "
            f"**{r['legitimate_task_success_rate'] * 100:.2f}%** | "
            f"{d['legitimate_succeeded']} / {d['legitimate_attempts']} |"
        ),
        (
            f"| False-Block Rate | **{r['false_block_rate'] * 100:.2f}%** | "
            f"{d['false_blocks']} / {d['legitimate_attempts']} |"
        ),
        (
            f"| Policy Decision Accuracy | **{r['policy_decision_accuracy'] * 100:.2f}%** | "
            f"{d['policy_correct']} / {d['policy_cases']} |"
        ),
        (
            "| Outcome Verification Accuracy | "
            f"**{r['outcome_verification_accuracy'] * 100:.2f}%** | "
            f"{d['verification_correct']} / {d['verification_cases']} |"
        ),
        "",
        "## Latency Breakdown (Milliseconds)",
        "",
        "| Stage | Samples | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |",
        "|---|---|---|---|---|---|",
        (
            f"| Gateway Total Request | {lat['gateway_total']['samples']} | "
            f"{lat['gateway_total']['p50_ms']} | {lat['gateway_total']['p95_ms']} | "
            f"{lat['gateway_total']['max_ms']} | {lat['gateway_total']['mean_ms']} |"
        ),
        (
            "| Gateway Overhead (excl. Adapter) | "
            f"{lat['gateway_overhead_excluding_tool']['samples']} | "
            f"{lat['gateway_overhead_excluding_tool']['p50_ms']} | "
            f"{lat['gateway_overhead_excluding_tool']['p95_ms']} | "
            f"{lat['gateway_overhead_excluding_tool']['max_ms']} | "
            f"{lat['gateway_overhead_excluding_tool']['mean_ms']} |"
        ),
        (
            f"| Pure PolicyEngine.evaluate() | {lat['policy_engine_eval']['samples']} | "
            f"{lat['policy_engine_eval']['p50_ms']} | "
            f"{lat['policy_engine_eval']['p95_ms']} | "
            f"{lat['policy_engine_eval']['max_ms']} | "
            f"{lat['policy_engine_eval']['mean_ms']} |"
        ),
        (
            "| Controlled Tool Adapter Execution | "
            f"{lat['tool_adapter_execution']['samples']} | "
            f"{lat['tool_adapter_execution']['p50_ms']} | "
            f"{lat['tool_adapter_execution']['p95_ms']} | "
            f"{lat['tool_adapter_execution']['max_ms']} | "
            f"{lat['tool_adapter_execution']['mean_ms']} |"
        ),
        "",
        "## Scenario Results",
        "",
        "| ID | Class | Category | Expected | Actual | Result | Latency (ms) |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in report["scenarios"]:
        status_label = "PASS" if s["passed"] else "FAIL"
        lines.append(
            f"| `{s['test_id']}` | {s['classification']} | `{s['category']}` | "
            f"`{s['expected_decision']}` / `{s['expected_execution_behavior']}` | "
            f"`{s['actual_decision']}` / `{s['actual_execution_behavior']}` | "
            f"**{status_label}** | {s['gateway_latency_ms']} |"
        )
    lines.append("")
    return "\n".join(lines)


async def run_security_benchmark(*, write_reports: bool = True) -> dict[str, Any]:
    """Execute the full 64-scenario benchmark in an isolated temporary environment."""
    admin_key = "axly_adm_benchmark_runner_key_0123456789abcdef"
    admin_headers = {"X-Admin-Key": admin_key}

    with tempfile.TemporaryDirectory(prefix="chaperone_bench_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_file = tmp_path / "benchmark.db"
        sandbox_root = ensure_demo_sandbox(tmp_path / "sandbox")
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir(parents=True, exist_ok=True)

        settings = Settings(
            env="test",
            log_json=False,
            database_url=f"sqlite+aiosqlite:///{db_file.as_posix()}",
            admin_api_key=SecretStr(admin_key),
            api_key_pepper=SecretStr("benchmark-pepper-secret"),
            api_key_hash_iterations=10_000,
            rate_limit_enabled=False,
            sandbox_dir=str(sandbox_root),
        )
        engine: AsyncEngine = build_engine(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        latency_tracker: dict[str, list[float]] = {"policy_ms": [], "tool_ms": []}
        real_policy_eval = PolicyEngine.evaluate
        real_dispatch = ExecutionDispatcher.dispatch

        def timed_policy_eval(self: PolicyEngine, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            res = real_policy_eval(self, **kwargs)
            latency_tracker["policy_ms"].append((time.perf_counter() - t0) * 1000.0)
            return res

        async def timed_dispatch(self: ExecutionDispatcher, *args: Any, **kwargs: Any) -> Any:
            t0 = time.perf_counter()
            res = await real_dispatch(self, *args, **kwargs)
            latency_tracker["tool_ms"].append((time.perf_counter() - t0) * 1000.0)
            return res

        app = create_app(settings=settings, engine=engine)
        session_factory = build_session_factory(engine)
        mcp_server = create_chaperone_mcp_server(session_factory=session_factory, settings=settings)

        try:
            with (
                patch.object(PolicyEngine, "evaluate", timed_policy_eval),
                patch.object(ExecutionDispatcher, "dispatch", timed_dispatch),
            ):
                async with app.router.lifespan_context(app):
                    async with AsyncClient(
                        transport=ASGITransport(app=app),
                        base_url="http://benchmark.local",
                    ) as client:
                        (
                            ag1_id,
                            ag1_key,
                            ag2_id,
                            ag2_key,
                            ag3_id,
                            ag3_key,
                        ) = await _seed_benchmark_entities(client, admin_headers)

                        async with connect_in_memory_mcp(mcp_server) as mcp_client:
                            async with session_factory() as session:
                                ctx = BenchmarkContext(
                                    client=client,
                                    mcp_client=mcp_client,
                                    session=session,
                                    settings=settings,
                                    admin_headers=admin_headers,
                                    primary_agent_id=ag1_id,
                                    primary_agent_key=ag1_key,
                                    secondary_agent_id=ag2_id,
                                    secondary_agent_key=ag2_key,
                                    disabled_agent_id=ag3_id,
                                    disabled_agent_key=ag3_key,
                                    sandbox_root=sandbox_root,
                                    outside_dir=outside_dir,
                                    latency_tracker=latency_tracker,
                                )
                                outcomes = await run_all_scenarios(ctx)
        finally:
            await engine.dispose()

    metrics = _compute_metrics(outcomes)
    report: dict[str, Any] = {
        "benchmark_name": "AXLY Chaperone Security & Governance Benchmark",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count() or 1,
            "processor": platform.processor() or "unknown",
            "database_backend": "sqlite+aiosqlite (isolated benchmark instance)",
        },
        "metrics": metrics,
        "scenarios": [asdict(o) for o in outcomes],
    }

    if write_reports:
        await asyncio.to_thread(_write_report_files, report)

    return report


def _write_report_files(report: dict[str, Any]) -> None:
    """Persist machine-readable JSON and human-readable Markdown benchmark reports."""
    repo_root = Path(__file__).resolve().parents[3]
    out_dir = repo_root / "benchmarks" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "latest_benchmark.json"
    md_path = out_dir / "latest_benchmark.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown_report(report), encoding="utf-8")


def main() -> None:
    """CLI entrypoint for running the 64-scenario AXLY Chaperone security benchmark."""
    report = asyncio.run(run_security_benchmark(write_reports=True))
    summary = {
        "timestamp_utc": report["timestamp_utc"],
        "counts": report["metrics"]["counts"],
        "rates": report["metrics"]["rates"],
        "latency": report["metrics"]["latency"],
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

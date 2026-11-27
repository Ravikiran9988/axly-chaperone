"""Automated tests for the 64-scenario Security Benchmark and 4-scenario Hackathon Demo."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from app.benchmark.runner import run_security_benchmark
from app.core.config import Settings
from app.core.database import build_session_factory
from app.demo.hackathon_demo import run_hackathon_demo


@pytest.mark.asyncio
async def test_security_benchmark_meets_targets_and_zero_failures() -> None:
    report = await run_security_benchmark(write_reports=False)
    counts = report["metrics"]["counts"]
    rates = report["metrics"]["rates"]
    latency = report["metrics"]["latency"]

    assert counts["total_scenarios"] >= 60
    assert counts["malicious_scenarios"] >= 30
    assert counts["legitimate_scenarios"] >= 30
    assert counts["failed_scenarios"] == 0
    assert counts["skipped_scenarios"] == 0

    assert rates["security_blocking_rate"] == 1.0
    assert rates["legitimate_task_success_rate"] == 1.0
    assert rates["false_block_rate"] == 0.0
    assert rates["policy_decision_accuracy"] == 1.0
    assert rates["outcome_verification_accuracy"] == 1.0

    assert latency["gateway_total"]["samples"] >= 60
    assert latency["policy_engine_eval"]["samples"] > 0
    assert latency["tool_adapter_execution"]["samples"] > 0


@pytest.mark.asyncio
async def test_hackathon_four_scenario_demo_end_to_end(
    test_engine: AsyncEngine,
    test_settings: Settings,
) -> None:
    factory = build_session_factory(test_engine)
    report = await run_hackathon_demo(
        session_factory=factory,
        settings=test_settings,
        approve_scenario_c=True,
    )

    assert report.scenario_a_legitimate["decision"] == "ALLOW"
    assert report.scenario_a_legitimate["status"] == "EXECUTED"
    assert report.scenario_a_legitimate["verification_status"] == "VERIFIED"
    assert "INV-2026-001" in report.scenario_a_legitimate["summary"]

    assert report.scenario_b_prompt_injection["injection_signal_detected"] is True
    assert report.scenario_b_prompt_injection["private_read_decision"] == "DENY"
    assert report.scenario_b_prompt_injection["private_read_status"] == "BLOCKED"
    assert report.scenario_b_prompt_injection["exfil_email_decision"] == "DENY"
    assert report.scenario_b_prompt_injection["exfil_email_status"] == "BLOCKED"
    assert report.scenario_b_prompt_injection["unauthorized_emails_persisted"] == 0

    assert report.scenario_c_human_approval["initial_decision"] == "REQUIRE_APPROVAL"
    assert report.scenario_c_human_approval["initial_status"] == "PENDING"
    assert report.scenario_c_human_approval["final_status"] == "executed"
    assert report.scenario_c_human_approval["verification_status"] == "verified"

    assert report.scenario_d_failed_verification["decision"] == "ALLOW"
    assert report.scenario_d_failed_verification["status"] == "FAILED"
    assert report.scenario_d_failed_verification["verification_status"] == "FAILED"

    assert report.audit_integrity["intact"] is True
    assert report.audit_integrity["tampered"] == 0
    assert report.secrets_leaked is False

"""Tests verifying Alembic Phase 1 & Phase 2 migrations (upgrade, downgrade, PostgreSQL DDL)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect


def _run_alembic(*args: str, db_url: str) -> subprocess.CompletedProcess[str]:
    backend_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["CHAPERONE_DATABASE_URL"] = db_url
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "alembic", *args],
        cwd=backend_root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


def test_alembic_upgrade_and_downgrade_on_isolated_db(tmp_path: Path) -> None:
    db_path = tmp_path / "migration_test.db"
    async_url = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    sync_url = f"sqlite:///{db_path.as_posix()}"

    _run_alembic("upgrade", "head", db_url=async_url)

    sync_engine = create_engine(sync_url)
    try:
        tables = set(inspect(sync_engine).get_table_names())
        assert {
            "agents",
            "admin_users",
            "admin_sessions",
            "tools",
            "policies",
            "audit_events",
            "audit_chain_state",
            "approval_requests",
            "verification_records",
            "mock_emails",
            "demo_invoices",
            "demo_tasks",
            "execution_idempotency",
            "alembic_version",
        } <= tables
    finally:
        sync_engine.dispose()

    _run_alembic("downgrade", "base", db_url=async_url)

    sync_engine = create_engine(sync_url)
    try:
        tables_after = set(inspect(sync_engine).get_table_names())
        assert "agents" not in tables_after
        assert "admin_users" not in tables_after
        assert "admin_sessions" not in tables_after
        assert "audit_chain_state" not in tables_after
        assert "approval_requests" not in tables_after
        assert "verification_records" not in tables_after
        assert "audit_events" not in tables_after
    finally:
        sync_engine.dispose()


def test_alembic_offline_postgresql_ddl_generation() -> None:
    result = _run_alembic(
        "upgrade",
        "head",
        "--sql",
        db_url="postgresql+asyncpg://postgres:placeholder@localhost:5432/axly_chaperone",
    )
    ddl = result.stdout
    assert "CREATE TABLE agents" in ddl
    assert "CREATE TABLE tools" in ddl
    assert "CREATE TABLE policies" in ddl
    assert "CREATE TABLE audit_events" in ddl
    assert "CREATE TABLE approval_requests" in ddl
    assert "CREATE TABLE verification_records" in ddl
    assert "CREATE TABLE mock_emails" in ddl
    assert "CREATE TABLE demo_invoices" in ddl
    assert "JSONB" in ddl

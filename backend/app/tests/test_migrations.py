"""Tests verifying Alembic initial migration upgrade, downgrade, and PostgreSQL DDL output."""

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
        assert {"agents", "tools", "policies", "audit_events", "alembic_version"} <= tables
    finally:
        sync_engine.dispose()

    _run_alembic("downgrade", "base", db_url=async_url)

    sync_engine = create_engine(sync_url)
    try:
        tables_after = set(inspect(sync_engine).get_table_names())
        assert "agents" not in tables_after
        assert "tools" not in tables_after
        assert "policies" not in tables_after
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
    assert "JSONB" in ddl

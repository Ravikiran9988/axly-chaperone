"""Shared pytest fixtures using an isolated temporary test database."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.adapters.file_adapter import ensure_demo_sandbox
from app.core.config import Settings
from app.core.database import Base, build_engine, build_session_factory
from app.main import create_app

TEST_ADMIN_KEY = "axly_adm_test_admin_key_0123456789abcdef_secure"


@pytest_asyncio.fixture
async def test_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Provide an isolated database engine per test (PostgreSQL if configured, else temp SQLite)."""
    explicit_pg_url = os.environ.get("CHAPERONE_TEST_DATABASE_URL")
    if explicit_pg_url:
        engine = build_engine(explicit_pg_url)
    else:
        db_file = tmp_path / "chaperone_test.db"
        engine = build_engine(f"sqlite+aiosqlite:///{db_file.as_posix()}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield engine
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    """Create deterministic test settings with low PBKDF2 iterations and isolated sandbox."""
    sandbox_dir = ensure_demo_sandbox(tmp_path / "sandbox")
    return Settings(
        env="test",
        log_json=False,
        database_url="sqlite+aiosqlite:///unused_in_test.db",
        admin_api_key=SecretStr(TEST_ADMIN_KEY),
        api_key_pepper=SecretStr("test_pepper_value_for_hmac"),
        api_key_hash_iterations=10_000,
        rate_limit_enabled=False,
        cors_origins=["http://localhost:3000"],
        sandbox_dir=str(sandbox_dir),
    )


@pytest_asyncio.fixture
async def db_session(test_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Provide a direct AsyncSession for database-level assertions in tests."""
    factory = build_session_factory(test_engine)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(
    test_engine: AsyncEngine,
    test_settings: Settings,
) -> AsyncIterator[AsyncClient]:
    """Provide an HTTPX AsyncClient wired to a fresh isolated FastAPI app."""
    app = create_app(settings=test_settings, engine=test_engine)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as async_client:
            yield async_client


@pytest.fixture
def admin_headers() -> dict[str, str]:
    """Return valid X-Admin-Key headers for administrative test endpoints."""
    return {"X-Admin-Key": TEST_ADMIN_KEY}

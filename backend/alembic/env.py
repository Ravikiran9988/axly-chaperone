"""Alembic async environment configuration for AXLY Chaperone."""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

import app.models  # noqa: F401  # Register all ORM models on Base.metadata
from alembic import context
from app.core.config import Settings
from app.core.database import Base
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_database_url() -> str:
    """Resolve database URL from Alembic option override or CHAPERONE_DATABASE_URL."""
    explicit_url = config.get_main_option("sqlalchemy.url")
    env_url = os.environ.get("CHAPERONE_DATABASE_URL")
    if env_url:
        return env_url
    if explicit_url and "CHANGE_ME" not in explicit_url:
        return explicit_url
    return Settings().database_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode to emit SQL DDL without a live DB connection."""
    url = _resolve_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations synchronously against a borrowed async connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine and run migrations inside an async connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _resolve_database_url()
    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

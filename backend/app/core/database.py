"""Async SQLAlchemy 2.x database engine, session factory, and declarative base."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from sqlalchemy import MetaData, event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def build_engine(
    database_url: str,
    *,
    echo: bool = False,
    pool_size: int = 10,
    max_overflow: int = 20,
) -> AsyncEngine:
    """Construct an AsyncEngine with dialect-appropriate pooling options."""
    kwargs: dict[str, Any] = {
        "echo": echo,
        "pool_pre_ping": True,
    }
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"timeout": 30}
    else:
        kwargs["pool_size"] = pool_size
        kwargs["max_overflow"] = max_overflow
        if database_url.startswith("postgresql"):
            kwargs["connect_args"] = {"command_timeout": 30, "timeout": 10}
    engine = create_async_engine(database_url, **kwargs)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine.sync_engine, "connect")
        def _configure_sqlite_pragma(dbapi_connection: Any, _connection_record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA busy_timeout=30000")
                if ":memory:" not in database_url:
                    cursor.execute("PRAGMA journal_mode=WAL")
            finally:
                cursor.close()

    return engine


def build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession per HTTP request from app state."""
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session


async def check_database_connectivity(session: AsyncSession) -> bool:
    """Verify database connectivity by executing a lightweight SELECT 1 probe."""
    result = await session.execute(text("SELECT 1"))
    return result.scalar_one() == 1

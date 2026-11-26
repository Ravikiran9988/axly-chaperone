"""Portable custom SQLAlchemy column types for PostgreSQL and isolated test DBs."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Dialect, TypeDecorator


def utc_now() -> datetime:
    """Return current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC DateTime that guarantees aware UTC datetimes across backends."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

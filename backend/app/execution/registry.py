"""In-process registry mapping registered Chaperone tool names to controlled adapters."""

from __future__ import annotations

from app.adapters.base import BaseToolAdapter
from app.adapters.database_adapter import DatabaseToolAdapter
from app.adapters.email_adapter import EmailToolAdapter
from app.adapters.file_adapter import FileToolAdapter


class AdapterRegistry:
    """Registry of approved, non-arbitrary Phase 2 execution adapters."""

    def __init__(self, adapters: list[BaseToolAdapter] | None = None) -> None:
        items = adapters or [
            FileToolAdapter(),
            EmailToolAdapter(),
            DatabaseToolAdapter(),
        ]
        self._adapters: dict[str, BaseToolAdapter] = {
            adapter.tool_name: adapter for adapter in items
        }

    def get(self, tool_name: str) -> BaseToolAdapter | None:
        """Return adapter registered for tool_name, or None if no controlled adapter exists."""
        return self._adapters.get(tool_name)

    def list_tool_names(self) -> list[str]:
        """Return sorted list of tool names backed by controlled adapters."""
        return sorted(self._adapters.keys())

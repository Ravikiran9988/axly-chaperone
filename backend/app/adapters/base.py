"""Common interface and execution data structures for controlled tool adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings


class AdapterValidationError(ValueError):
    """Raised when tool-specific arguments or actions fail adapter-level validation."""


class AdapterSecurityError(PermissionError):
    """Raised when an adapter detects sandbox escape, symlink abuse, or disallowed target."""


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Controlled execution context passed from ExecutionDispatcher to an adapter."""

    correlation_id: str
    agent_id: UUID
    tool_name: str
    action: str
    resource: str
    arguments: dict[str, Any]
    session: AsyncSession
    settings: Settings
    approval_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class AdapterExecutionResult:
    """Structured result emitted by a controlled tool adapter."""

    success: bool
    summary: str
    output: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None


class BaseToolAdapter(ABC):
    """Abstract base class enforcing validation, resource checks, and controlled execution."""

    tool_name: str
    category: str
    supported_actions: frozenset[str]

    @abstractmethod
    def validate_resource(self, action: str, resource: str, arguments: dict[str, Any]) -> str:
        """Validate and canonicalize the resource independently at adapter level."""

    @abstractmethod
    def validate_inputs(
        self,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        *,
        settings: Settings,
    ) -> dict[str, Any]:
        """Validate action and tool arguments against adapter-specific limits."""

    @abstractmethod
    async def execute(self, context: ExecutionContext) -> AdapterExecutionResult:
        """Execute the validated tool operation within sandboxed constraints."""

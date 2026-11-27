"""Execution domain models returned by the controlled ExecutionDispatcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import ExecutionStatus


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Outcome of controlled adapter execution (sanitized for audit and caller responses)."""

    status: ExecutionStatus
    summary: str
    output: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None
    timed_out: bool = False

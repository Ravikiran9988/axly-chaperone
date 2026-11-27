"""Strict Pydantic v2 schemas for MCP tool calls routed through Chaperone."""

from __future__ import annotations

import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class McpToolCallEnvelope(BaseModel):
    """Base MCP tool call contract enforcing concrete action, resource, and auth metadata."""

    model_config = ConfigDict(extra="forbid")

    resource: str = Field(min_length=1, max_length=1024)
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_api_key: str | None = Field(
        default=None,
        max_length=256,
        description="Agent X-Agent-Key credential (optional if configured on stdio server).",
    )
    correlation_id: str | None = Field(
        default=None,
        description="Optional correlation ID propagated across MCP and Chaperone audit logs.",
    )
    approval_id: UUID | None = Field(
        default=None,
        description="Optional approved request UUID for two-step human-approved execution.",
    )

    @field_validator("correlation_id")
    @classmethod
    def validate_correlation_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not _CORRELATION_ID_RE.fullmatch(cleaned):
            raise ValueError("correlation_id must be 8-64 chars of [A-Za-z0-9._-].")
        return cleaned


class McpFileToolInput(McpToolCallEnvelope):
    """MCP schema for file_tool."""

    action: Literal["read", "write", "list"]


class McpEmailToolInput(McpToolCallEnvelope):
    """MCP schema for email_tool."""

    action: Literal["create_draft", "send", "read"]


class McpDatabaseToolInput(McpToolCallEnvelope):
    """MCP schema for database_tool."""

    action: Literal["read", "create", "update"]

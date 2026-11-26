"""Pydantic v2 schemas for the Phase 1 Gateway evaluation endpoint."""

from __future__ import annotations

import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,126}$")
_GATEWAY_ACTION_RE = re.compile(r"^[a-z][a-z0-9_:-]{0,62}$")


class GatewayEvaluateRequest(BaseModel):
    """Tool access evaluation request submitted by an authenticated AI agent."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=2, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    resource: str = Field(min_length=1, max_length=1024)
    arguments: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not _TOOL_NAME_RE.fullmatch(cleaned):
            raise ValueError("Invalid tool_name format.")
        return cleaned

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not _GATEWAY_ACTION_RE.fullmatch(cleaned):
            raise ValueError(
                "Action must be a concrete lowercase identifier (wildcards forbidden)."
            )
        return cleaned


class GatewayEvaluateResponse(BaseModel):
    """Deterministic policy decision returned by POST /api/v1/gateway/evaluate."""

    model_config = ConfigDict(frozen=True)

    correlation_id: str
    decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    reason: str
    tool_name: str
    action: str
    resource: str
    agent_id: UUID
    matched_policy_id: UUID | None = None
    execution_status: str = "not_executed"

"""Pydantic v2 schemas for agent registration, retrieval, and status management."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import AgentStatus

_AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{1,126}[A-Za-z0-9]$")


class AgentCreateRequest(BaseModel):
    """Payload to register a new AI agent identity."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=1000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not _AGENT_NAME_RE.fullmatch(cleaned):
            raise ValueError(
                "Agent name must be 2-128 characters starting/ending with alphanumeric "
                "characters and containing only letters, digits, spaces, '.', '_', or '-'."
            )
        return cleaned

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class AgentStatusUpdateRequest(BaseModel):
    """Payload to activate or disable an agent."""

    model_config = ConfigDict(extra="forbid")

    status: AgentStatus


class AgentResponse(BaseModel):
    """Public agent representation (never exposes api_key or api_key_hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    key_prefix: str
    status: AgentStatus
    created_at: datetime
    updated_at: datetime


class AgentCreateResponse(AgentResponse):
    """Returned ONCE upon registration containing the plaintext API key."""

    api_key: str

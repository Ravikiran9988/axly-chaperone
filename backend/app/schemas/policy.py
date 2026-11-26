"""Pydantic v2 schemas for deterministic authorization policies."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import PolicyDecision
from app.security.resource_validator import validate_resource_scope

_POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:-]{1,126}[A-Za-z0-9]$")
_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,126}$")
_POLICY_ACTION_RE = re.compile(r"^(?:\*|[a-z][a-z0-9_:-]{0,62})$")


def _normalize_decision(value: PolicyDecision | str) -> PolicyDecision:
    if isinstance(value, PolicyDecision):
        return value
    if isinstance(value, str):
        return PolicyDecision(value.strip().lower())
    raise ValueError("Invalid policy decision.")


class PolicyCreateRequest(BaseModel):
    """Payload to create an authorization policy."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    agent_id: UUID | None = None
    tool_name: str = Field(min_length=2, max_length=128)
    action: str = Field(min_length=1, max_length=64)
    resource_scope: str = Field(min_length=1, max_length=512)
    decision: PolicyDecision
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=10000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not _POLICY_NAME_RE.fullmatch(cleaned):
            raise ValueError("Policy name contains unsupported characters.")
        return cleaned

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
        if not _POLICY_ACTION_RE.fullmatch(cleaned):
            raise ValueError("Action must be '*' or a lowercase action identifier.")
        return cleaned

    @field_validator("resource_scope")
    @classmethod
    def validate_scope(cls, value: str) -> str:
        return validate_resource_scope(value)

    @field_validator("decision", mode="before")
    @classmethod
    def validate_decision(cls, value: PolicyDecision | str) -> PolicyDecision:
        return _normalize_decision(value)


class PolicyUpdateRequest(BaseModel):
    """Payload to update an existing policy (increments policy version)."""

    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, max_length=1000)
    action: str | None = Field(default=None, min_length=1, max_length=64)
    resource_scope: str | None = Field(default=None, min_length=1, max_length=512)
    decision: PolicyDecision | None = None
    enabled: bool | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        if not _POLICY_ACTION_RE.fullmatch(cleaned):
            raise ValueError("Action must be '*' or a lowercase action identifier.")
        return cleaned

    @field_validator("resource_scope")
    @classmethod
    def validate_scope(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_resource_scope(value)

    @field_validator("decision", mode="before")
    @classmethod
    def validate_decision(cls, value: PolicyDecision | str | None) -> PolicyDecision | None:
        if value is None:
            return None
        return _normalize_decision(value)

    @model_validator(mode="after")
    def validate_non_empty_patch(self) -> PolicyUpdateRequest:
        if (
            self.description is None
            and self.action is None
            and self.resource_scope is None
            and self.decision is None
            and self.enabled is None
            and self.priority is None
        ):
            raise ValueError("At least one field must be provided for policy update.")
        return self


class PolicyResponse(BaseModel):
    """Public representation of an authorization policy."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str | None
    agent_id: UUID | None
    tool_name: str
    action: str
    resource_scope: str
    decision: PolicyDecision
    enabled: bool
    priority: int
    version: int
    created_at: datetime
    updated_at: datetime

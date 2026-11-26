"""Pydantic v2 schemas for the Tool Registry API."""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import RiskLevel

_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,126}$")
_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


class ToolCreateRequest(BaseModel):
    """Payload to register a tool definition."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=128)
    description: str = Field(min_length=1, max_length=1000)
    category: str = Field(min_length=2, max_length=64)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not _TOOL_NAME_RE.fullmatch(cleaned):
            raise ValueError(
                "Tool name must start with a lowercase letter and contain only "
                "lowercase letters, digits, '.', '_', or '-'."
            )
        return cleaned

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not _CATEGORY_RE.fullmatch(cleaned):
            raise ValueError(
                "Category must start with a lowercase letter and contain only "
                "lowercase letters, digits, '_', or '-'."
            )
        return cleaned

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Tool description cannot be empty.")
        return cleaned


class ToolUpdateRequest(BaseModel):
    """Payload to update mutable attributes of a registered tool."""

    model_config = ConfigDict(extra="forbid")

    description: str | None = Field(default=None, min_length=1, max_length=1000)
    category: str | None = Field(default=None, min_length=2, max_length=64)
    risk_level: RiskLevel | None = None
    enabled: bool | None = None

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        if not _CATEGORY_RE.fullmatch(cleaned):
            raise ValueError(
                "Category must start with a lowercase letter and contain only "
                "lowercase letters, digits, '_', or '-'."
            )
        return cleaned

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Tool description cannot be empty.")
        return cleaned

    @model_validator(mode="after")
    def validate_non_empty_patch(self) -> ToolUpdateRequest:
        if (
            self.description is None
            and self.category is None
            and self.risk_level is None
            and self.enabled is None
        ):
            raise ValueError("At least one field must be provided for tool update.")
        return self


class ToolResponse(BaseModel):
    """Public representation of a registered tool definition."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str
    category: str
    risk_level: RiskLevel
    enabled: bool
    created_at: datetime
    updated_at: datetime

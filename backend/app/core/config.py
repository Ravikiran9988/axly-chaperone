"""Environment-based application configuration with fail-closed security validation."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings loaded from environment variables and optional .env file."""

    model_config = SettingsConfigDict(
        env_prefix="CHAPERONE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: Literal["development", "staging", "production", "test"] = "development"
    app_name: str = "AXLY Chaperone"
    app_version: str = "0.1.0"
    log_level: str = "INFO"
    log_json: bool = True

    # PostgreSQL async database URL
    database_url: str = "postgresql+asyncpg://postgres:CHANGE_ME@localhost:5432/axly_chaperone"
    db_echo: bool = False
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=100)

    # Admin bootstrap key — intentionally has no hardcoded default
    admin_api_key: SecretStr | None = None

    # Optional global pepper mixed into agent API key hashes
    api_key_pepper: SecretStr | None = None
    api_key_hash_iterations: int = Field(default=200_000, ge=10_000, le=2_000_000)

    # Restrictive CORS defaults
    cors_origins: list[str] = Field(default_factory=list)
    cors_allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PATCH"])
    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["Content-Type", "X-Admin-Key", "X-Agent-Key", "X-Correlation-ID"]
    )

    # Phase 1 in-memory rate limiting strategy
    rate_limit_enabled: bool = True
    rate_limit_requests: int = Field(default=120, ge=1, le=100_000)
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=86_400)

    # Security limits on gateway payloads
    max_resource_length: int = Field(default=1024, ge=64, le=4096)

    # Phase 2: Sandbox, approvals, execution timeouts, and MCP defaults
    sandbox_dir: str = "sandbox_data"
    approval_ttl_seconds: int = Field(default=900, ge=10, le=604_800)
    tool_execution_timeout_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    max_file_size_bytes: int = Field(default=1_048_576, ge=1024, le=10_485_760)
    max_argument_payload_bytes: int = Field(default=32_768, ge=512, le=262_144)
    mcp_agent_key: SecretStr | None = None

    @model_validator(mode="after")
    def validate_security_posture(self) -> Settings:
        """Fail closed on unsafe configurations in staging/production."""
        if self.env in {"production", "staging"}:
            if (
                self.admin_api_key is None
                or len(self.admin_api_key.get_secret_value().strip()) < 32
            ):
                raise ValueError(
                    "CHAPERONE_ADMIN_API_KEY must be configured with at least 32 characters "
                    "in staging/production environments."
                )
            if "*" in self.cors_origins:
                raise ValueError(
                    "Wildcard '*' CORS origins are prohibited in staging/production environments."
                )
            if "CHANGE_ME" in self.database_url:
                raise ValueError(
                    "CHAPERONE_DATABASE_URL contains placeholder credentials in staging/production."
                )
        return self

    def get_admin_api_key(self) -> str | None:
        """Return configured admin API key value if present and non-empty."""
        if self.admin_api_key is None:
            return None
        value = self.admin_api_key.get_secret_value().strip()
        return value or None

    def get_api_key_pepper(self) -> str | None:
        """Return optional global pepper value if configured."""
        if self.api_key_pepper is None:
            return None
        value = self.api_key_pepper.get_secret_value()
        return value or None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()

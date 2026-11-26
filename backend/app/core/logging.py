"""Structured logging configuration with automatic secret redaction."""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"axly_(?:ag|adm)_[A-Za-z0-9_-]+"),
    re.compile(
        r"(?i)(x-agent-key|x-admin-key|authorization|api_key|password)\s*[:=]\s*[^\s,;\"']+"
    ),
    re.compile(r"pbkdf2_sha256\$\d+\$[A-Za-z0-9_=-]+\$[A-Za-z0-9_=-]+"),
)


def redact_secrets(text: str) -> str:
    """Scrub API keys, credential headers, and hashes from arbitrary log strings."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


class SecretRedactionFilter(logging.Filter):
    """Logging filter that guarantees secrets are redacted before formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(arg) if isinstance(arg, str) else arg for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
        return True


class JsonLogFormatter(logging.Formatter):
    """Minimal structured JSON log formatter including active correlation ID."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage()),
            "correlation_id": getattr(record, "correlation_id", None) or correlation_id_var.get(),
        }
        for attr in ("method", "path", "status_code", "duration_ms", "agent_id", "decision"):
            value = getattr(record, attr, None)
            if value is not None:
                payload[attr] = value
        if record.exc_info:
            payload["exception"] = redact_secrets(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(*, level: str = "INFO", json_logs: bool = True) -> None:
    """Configure root and application loggers consistently."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())
    root_logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter())
    if json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        )
    root_logger.addHandler(handler)

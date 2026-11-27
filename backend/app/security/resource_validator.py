"""Security-critical resource normalization, validation, and safe scope matching."""

from __future__ import annotations

import posixpath
import re
from typing import Any
from urllib.parse import unquote, urlsplit

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)
_ENCODED_TRAVERSAL_RE = re.compile(r"%(?:2e|2f|5c|00|25)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_DB_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,2}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")

_FILESYSTEM_ARG_KEYS = frozenset(
    {
        "path",
        "file_path",
        "filepath",
        "file",
        "filename",
        "target",
        "target_path",
        "source",
        "source_path",
        "destination",
        "destination_path",
        "dest_path",
        "directory",
        "dir",
        "dir_path",
    }
)
_NETWORK_ARG_KEYS = frozenset({"url", "uri", "endpoint", "target_url", "href"})
_COMMUNICATION_ARG_KEYS = frozenset(
    {"to", "recipient", "recipients", "email", "target", "channel", "cc", "bcc"}
)
_DATABASE_ARG_KEYS = frozenset({"table", "collection", "dataset", "resource", "target"})
_DATABASE_RAW_SQL_KEYS = frozenset({"sql", "query", "raw_sql", "statement", "command"})
_GENERIC_ARG_KEYS = frozenset(
    {"resource", "target", "path", "url", "uri", "file", "table", "recipient", "to"}
)


class ResourceValidationError(ValueError):
    """Raised when a resource identifier or tool argument is unsafe, ambiguous, or mismatched."""


def _reject_control_and_encoding(value: str, *, field_name: str = "resource") -> str:
    if not isinstance(value, str):
        raise ResourceValidationError(f"Unsafe {field_name}: value must be a string.")
    stripped = value.strip()
    if not stripped or stripped != value:
        raise ResourceValidationError(
            f"Ambiguous {field_name}: empty or leading/trailing whitespace is not permitted."
        )
    if len(stripped) > 1024:
        raise ResourceValidationError(f"Unsafe {field_name}: exceeds maximum length of 1024.")
    if _CONTROL_CHAR_RE.search(stripped):
        raise ResourceValidationError(f"Unsafe {field_name}: control characters are prohibited.")
    if _ENCODED_TRAVERSAL_RE.search(stripped):
        raise ResourceValidationError(
            f"Unsafe {field_name}: percent-encoded path or null sequences are prohibited."
        )
    decoded_once = unquote(stripped)
    if decoded_once != stripped and (
        ".." in decoded_once or "\\" in decoded_once or "\x00" in decoded_once
    ):
        raise ResourceValidationError(
            f"Unsafe {field_name}: encoded traversal or separator sequences are prohibited."
        )
    return stripped


def normalize_filesystem_resource(raw_path: str, *, field_name: str = "resource") -> str:
    """Validate and canonicalize a relative POSIX-style filesystem resource path."""
    cleaned = _reject_control_and_encoding(raw_path, field_name=field_name)
    if "\\" in cleaned:
        raise ResourceValidationError(
            f"Unsafe {field_name}: backslashes are prohibited in resource paths."
        )
    if _WINDOWS_DRIVE_RE.match(cleaned) or cleaned.startswith("/") or ":" in cleaned:
        raise ResourceValidationError(
            f"Unsafe {field_name}: absolute, colon/ADS, or drive-prefixed paths are prohibited."
        )
    segments = cleaned.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            raise ResourceValidationError(
                f"Unsafe {field_name}: path traversal or empty/dot segments are prohibited."
            )
        stem = segment.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise ResourceValidationError(
                f"Unsafe {field_name}: reserved OS device name segment '{segment}' is prohibited."
            )
    normalized = posixpath.normpath(cleaned)
    if normalized != cleaned or normalized.startswith("..") or normalized.startswith("/"):
        raise ResourceValidationError(
            f"Ambiguous {field_name}: non-canonical path representation rejected."
        )
    return normalized


def normalize_network_resource(raw_url: str, *, field_name: str = "resource") -> str:
    """Validate and canonicalize an HTTP(S) URL resource without credentials or traversal."""
    cleaned = _reject_control_and_encoding(raw_url, field_name=field_name)
    if "\\" in cleaned:
        raise ResourceValidationError(f"Unsafe {field_name}: backslashes are prohibited in URLs.")
    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ResourceValidationError(
            f"Unsafe {field_name}: only http and https URL schemes are supported."
        )
    if parsed.username is not None or parsed.password is not None:
        raise ResourceValidationError(
            f"Unsafe {field_name}: embedded credentials in URLs are prohibited."
        )
    if not parsed.hostname:
        raise ResourceValidationError(f"Invalid {field_name}: URL must include a valid hostname.")
    hostname = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ResourceValidationError(f"Invalid {field_name}: malformed URL port.") from exc

    default_port = 80 if scheme == "http" else 443
    netloc = hostname if (port is None or port == default_port) else f"{hostname}:{port}"

    raw_path = parsed.path or "/"
    if not raw_path.startswith("/"):
        raise ResourceValidationError(f"Invalid {field_name}: URL path must be rooted.")
    path_segments = raw_path.split("/")[1:]
    # Allow a trailing empty segment on root/directory paths; reject internal '//' or '.'/'..'
    for idx, segment in enumerate(path_segments):
        if segment in (".", ".."):
            raise ResourceValidationError(
                f"Unsafe {field_name}: path traversal segments are prohibited in URLs."
            )
        if segment == "" and idx < len(path_segments) - 1:
            raise ResourceValidationError(
                f"Ambiguous {field_name}: empty path segments in URL are prohibited."
            )

    canonical_url = f"{scheme}://{netloc}{raw_path}"
    if parsed.query:
        canonical_url = f"{canonical_url}?{parsed.query}"
    return canonical_url


def normalize_communication_resource(raw_target: str, *, field_name: str = "resource") -> str:
    """Validate and canonicalize an email address or messaging channel target."""
    cleaned = _reject_control_and_encoding(raw_target, field_name=field_name)
    if any(ch in cleaned for ch in (",", ";", " ", "\t", "\\", "/")):
        raise ResourceValidationError(
            f"Unsafe {field_name}: whitespace, delimiters, or separators are prohibited."
        )
    if "@" in cleaned:
        if not _EMAIL_RE.fullmatch(cleaned):
            raise ResourceValidationError(f"Invalid {field_name}: malformed email recipient.")
        local, domain = cleaned.split("@", 1)
        return f"{local}@{domain.lower()}"
    if ".." in cleaned:
        raise ResourceValidationError(f"Unsafe {field_name}: traversal sequences are prohibited.")
    return cleaned


def normalize_database_resource(raw_ident: str, *, field_name: str = "resource") -> str:
    """Validate a canonical database identifier such as 'table' or 'schema.table'."""
    cleaned = _reject_control_and_encoding(raw_ident, field_name=field_name)
    if not _DB_IDENT_RE.fullmatch(cleaned):
        raise ResourceValidationError(f"Unsafe {field_name}: invalid database resource identifier.")
    return cleaned


def normalize_generic_resource(raw_resource: str, *, field_name: str = "resource") -> str:
    """Validate and canonicalize a generic resource identifier without traversal or ambiguity."""
    cleaned = _reject_control_and_encoding(raw_resource, field_name=field_name)
    if "\\" in cleaned or cleaned.startswith("/") or _WINDOWS_DRIVE_RE.match(cleaned):
        raise ResourceValidationError(
            f"Unsafe {field_name}: backslashes, absolute paths, or drive prefixes are prohibited."
        )
    for segment in cleaned.split("/"):
        if segment in ("", ".", ".."):
            raise ResourceValidationError(
                f"Unsafe {field_name}: empty or dot traversal segments are prohibited."
            )
    return cleaned


def _resolve_category_kind(tool_category: str | None, tool_name: str) -> str:
    category = (tool_category or "").lower()
    name = tool_name.lower()
    if category in {"filesystem", "file", "storage"} or name.startswith(("file_", "fs_", "dir_")):
        return "filesystem"
    if category in {"network", "http", "web", "api"} or name.startswith(
        ("http_", "web_", "fetch_")
    ):
        return "network"
    if category in {"communication", "email", "messaging"} or name.startswith(
        ("email_", "mail_", "slack_", "msg_")
    ):
        return "communication"
    if category in {"database", "sql", "db"} or name.startswith(("db_", "sql_", "query_")):
        return "database"
    return "generic"


def _check_nested_resource_keys(
    args: dict[str, Any],
    *,
    keys: frozenset[str],
    canonical: str,
    normalizer: Any,
    allow_lists: bool = False,
) -> None:
    """Recursively verify any nested dicts/lists containing resource-bearing argument keys."""
    for key, val in args.items():
        if isinstance(val, dict):
            for nested_key, nested_val in val.items():
                if str(nested_key).lower() in keys and nested_val is not None:
                    values = (
                        nested_val
                        if (allow_lists and isinstance(nested_val, list))
                        else [nested_val]
                    )
                    if not values:
                        raise ResourceValidationError(
                            f"Unsafe empty list in 'arguments.{key}.{nested_key}'."
                        )
                    for item in values:
                        if not isinstance(item, str):
                            raise ResourceValidationError(
                                f"Unsafe nested argument '{key}.{nested_key}': expected string."
                            )
                        nested_canonical = normalizer(
                            item, field_name=f"arguments.{key}.{nested_key}"
                        )
                        if nested_canonical != canonical:
                            raise ResourceValidationError(
                                f"Resource mismatch between 'resource' and "
                                f"'arguments.{key}.{nested_key}'."
                            )
            _check_nested_resource_keys(
                val,
                keys=keys,
                canonical=canonical,
                normalizer=normalizer,
                allow_lists=allow_lists,
            )
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _check_nested_resource_keys(
                        item,
                        keys=keys,
                        canonical=canonical,
                        normalizer=normalizer,
                        allow_lists=allow_lists,
                    )


def validate_and_normalize_resource(
    *,
    tool_category: str | None,
    tool_name: str,
    resource: str,
    arguments: dict[str, Any] | None = None,
) -> str:
    """Normalize resource using tool-specific rules and verify consistency with arguments."""
    kind = _resolve_category_kind(tool_category, tool_name)
    args = arguments or {}
    if not isinstance(args, dict):
        raise ResourceValidationError("Tool arguments must be a JSON object.")

    if kind == "filesystem":
        canonical = normalize_filesystem_resource(resource)
        for key, raw_val in args.items():
            if str(key).lower() in _FILESYSTEM_ARG_KEYS and raw_val is not None:
                if not isinstance(raw_val, str):
                    raise ResourceValidationError(f"Unsafe argument '{key}': expected string path.")
                arg_canonical = normalize_filesystem_resource(
                    raw_val, field_name=f"arguments.{key}"
                )
                if arg_canonical != canonical:
                    raise ResourceValidationError(
                        f"Resource mismatch between 'resource' and 'arguments.{key}'."
                    )
        _check_nested_resource_keys(
            args,
            keys=_FILESYSTEM_ARG_KEYS,
            canonical=canonical,
            normalizer=normalize_filesystem_resource,
        )
        return canonical

    if kind == "network":
        canonical = normalize_network_resource(resource)
        parsed_canonical = urlsplit(canonical)
        for key, raw_val in args.items():
            lowered = str(key).lower()
            if lowered in _NETWORK_ARG_KEYS and raw_val is not None:
                if not isinstance(raw_val, str):
                    raise ResourceValidationError(f"Unsafe argument '{key}': expected string URL.")
                arg_canonical = normalize_network_resource(raw_val, field_name=f"arguments.{key}")
                if arg_canonical != canonical:
                    raise ResourceValidationError(
                        f"Resource mismatch between 'resource' and 'arguments.{key}'."
                    )
            elif lowered in {"host", "domain"} and raw_val is not None:
                if not isinstance(raw_val, str):
                    raise ResourceValidationError(f"Unsafe argument '{key}'.")
                if raw_val.strip().lower() != (parsed_canonical.hostname or ""):
                    raise ResourceValidationError(f"Resource host mismatch with 'arguments.{key}'.")
        _check_nested_resource_keys(
            args,
            keys=_NETWORK_ARG_KEYS,
            canonical=canonical,
            normalizer=normalize_network_resource,
        )
        return canonical

    if kind == "communication":
        canonical = normalize_communication_resource(resource)
        for key, raw_val in args.items():
            if str(key).lower() in _COMMUNICATION_ARG_KEYS and raw_val is not None:
                values = raw_val if isinstance(raw_val, list) else [raw_val]
                if not values:
                    raise ResourceValidationError(f"Unsafe empty list in 'arguments.{key}'.")
                for item in values:
                    if not isinstance(item, str):
                        raise ResourceValidationError(
                            f"Unsafe item in 'arguments.{key}': expected string."
                        )
                    item_canonical = normalize_communication_resource(
                        item, field_name=f"arguments.{key}"
                    )
                    if item_canonical != canonical:
                        raise ResourceValidationError(
                            f"Resource mismatch between 'resource' and 'arguments.{key}'."
                        )
        _check_nested_resource_keys(
            args,
            keys=_COMMUNICATION_ARG_KEYS,
            canonical=canonical,
            normalizer=normalize_communication_resource,
            allow_lists=True,
        )
        return canonical

    if kind == "database":
        canonical = normalize_database_resource(resource)
        for key, raw_val in args.items():
            lowered = str(key).lower()
            if lowered in _DATABASE_RAW_SQL_KEYS and raw_val is not None:
                raise ResourceValidationError(
                    f"Unsafe argument '{key}': arbitrary SQL statements are prohibited."
                )
            if lowered in _DATABASE_ARG_KEYS and raw_val is not None:
                if not isinstance(raw_val, str):
                    raise ResourceValidationError(f"Unsafe argument '{key}': expected string.")
                arg_canonical = normalize_database_resource(raw_val, field_name=f"arguments.{key}")
                if arg_canonical != canonical:
                    raise ResourceValidationError(
                        f"Resource mismatch between 'resource' and 'arguments.{key}'."
                    )
        _check_nested_resource_keys(
            args,
            keys=_DATABASE_ARG_KEYS,
            canonical=canonical,
            normalizer=normalize_database_resource,
        )
        return canonical

    canonical = normalize_generic_resource(resource)
    for key, raw_val in args.items():
        if str(key).lower() in _GENERIC_ARG_KEYS and raw_val is not None:
            if not isinstance(raw_val, str):
                raise ResourceValidationError(f"Unsafe argument '{key}': expected string.")
            arg_canonical = normalize_generic_resource(raw_val, field_name=f"arguments.{key}")
            if arg_canonical != canonical:
                raise ResourceValidationError(
                    f"Resource mismatch between 'resource' and 'arguments.{key}'."
                )
    _check_nested_resource_keys(
        args,
        keys=_GENERIC_ARG_KEYS,
        canonical=canonical,
        normalizer=normalize_generic_resource,
    )
    return canonical


def validate_resource_scope(scope: str) -> str:
    """Validate and canonicalize a policy resource_scope pattern without unsafe wildcards."""
    cleaned = _reject_control_and_encoding(scope, field_name="resource_scope")
    if len(cleaned) > 512:
        raise ValueError("resource_scope exceeds maximum length of 512.")
    if "?" in cleaned:
        raise ValueError("Question-mark wildcards are not permitted in resource_scope.")
    if cleaned == "*":
        return "*"

    if cleaned.startswith("*@"):
        domain = cleaned[2:].lower()
        if "*" in domain or not _DOMAIN_RE.fullmatch(domain):
            raise ValueError("Invalid domain wildcard scope; expected '*@domain.tld'.")
        return f"*@{domain}"

    if cleaned.endswith("/*"):
        prefix = cleaned[:-2]
        if "*" in prefix or not prefix:
            raise ValueError("Wildcards are only allowed as '*' or a single trailing '/*'.")
        if "://" in prefix:
            normalized_url = normalize_network_resource(f"{prefix}/", field_name="resource_scope")
            return f"{normalized_url}*" if normalized_url.endswith("/") else f"{normalized_url}/*"
        normalized_prefix = normalize_filesystem_resource(prefix, field_name="resource_scope")
        return f"{normalized_prefix}/*"

    if "*" in cleaned:
        raise ValueError(
            "Unsafe wildcard in resource_scope. Supported forms: "
            "'*', '<prefix>/*', '*@<domain>', or exact match."
        )

    if "://" in cleaned:
        return normalize_network_resource(cleaned, field_name="resource_scope")
    if "@" in cleaned:
        return normalize_communication_resource(cleaned, field_name="resource_scope")
    return normalize_generic_resource(cleaned, field_name="resource_scope")


def resource_matches_scope(scope: str, normalized_resource: str) -> bool:
    """Deterministically evaluate whether a normalized resource matches a validated policy scope."""
    if scope == "*":
        return True

    if scope.startswith("*@"):
        if normalized_resource.count("@") != 1:
            return False
        _, domain = normalized_resource.split("@", 1)
        return domain.lower() == scope[2:].lower()

    if scope.endswith("/*"):
        prefix = scope[:-2]
        if "://" in prefix:
            scope_parts = urlsplit(f"{prefix}/")
            res_parts = urlsplit(normalized_resource)
            if (
                scope_parts.scheme.lower() != res_parts.scheme.lower()
                or (scope_parts.hostname or "").lower() != (res_parts.hostname or "").lower()
                or scope_parts.port != res_parts.port
            ):
                return False
            scope_path_prefix = scope_parts.path.rstrip("/")
            if not scope_path_prefix:
                return True
            return res_parts.path == scope_path_prefix or res_parts.path.startswith(
                f"{scope_path_prefix}/"
            )
        return normalized_resource.startswith(f"{prefix}/")

    return normalized_resource == scope

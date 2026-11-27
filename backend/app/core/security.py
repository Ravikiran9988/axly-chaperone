"""Cryptographic primitives for API key generation, hashing, and constant-time comparison."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

API_KEY_PREFIX = "axly_ag"
KEY_ID_HEX_LENGTH = 16
HASH_ALGORITHM_ID = "pbkdf2_sha256"
SALT_BYTES = 16
SECRET_BYTES = 32

_API_KEY_PATTERN = re.compile(r"^axly_ag_([0-9a-f]{16})_([A-Za-z0-9_-]{32,128})$")


@dataclass(frozen=True, slots=True)
class GeneratedApiKey:
    """Newly generated agent API key material (raw_key must only be shown once)."""

    raw_key: str
    key_id: str
    key_hash: str
    key_prefix: str


def _derive_key_material(raw_key: str, pepper: str | None) -> bytes:
    """Mix optional server-side pepper using HMAC-SHA256 before PBKDF2 derivation."""
    raw_bytes = raw_key.encode("utf-8")
    if pepper:
        return hmac.new(pepper.encode("utf-8"), raw_bytes, hashlib.sha256).digest()
    return raw_bytes


def hash_api_key(
    raw_key: str,
    *,
    salt: bytes | None = None,
    iterations: int = 200_000,
    pepper: str | None = None,
) -> str:
    """Hash an API key using PBKDF2-HMAC-SHA256 with a random per-key salt."""
    salt_bytes = salt if salt is not None else secrets.token_bytes(SALT_BYTES)
    material = _derive_key_material(raw_key, pepper)
    digest = hashlib.pbkdf2_hmac("sha256", material, salt_bytes, iterations)
    salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode("ascii")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"{HASH_ALGORITHM_ID}${iterations}${salt_b64}${digest_b64}"


def generate_agent_api_key(
    *,
    iterations: int = 200_000,
    pepper: str | None = None,
) -> GeneratedApiKey:
    """Generate a high-entropy agent API key and its salted PBKDF2-HMAC-SHA256 hash."""
    key_id = secrets.token_hex(KEY_ID_HEX_LENGTH // 2)
    secret_part = secrets.token_urlsafe(SECRET_BYTES)
    raw_key = f"{API_KEY_PREFIX}_{key_id}_{secret_part}"
    key_hash = hash_api_key(raw_key, iterations=iterations, pepper=pepper)
    key_prefix = f"{API_KEY_PREFIX}_{key_id[:8]}..."
    return GeneratedApiKey(
        raw_key=raw_key,
        key_id=key_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
    )


def parse_agent_api_key(raw_key: str) -> tuple[str, str] | None:
    """Extract (key_id, secret_part) from a raw agent key or return None if malformed."""
    if not raw_key or len(raw_key) > 256:
        return None
    match = _API_KEY_PATTERN.fullmatch(raw_key.strip())
    if match is None:
        return None
    return match.group(1), match.group(2)


def verify_api_key(raw_key: str, stored_hash: str, *, pepper: str | None = None) -> bool:
    """Verify a presented raw API key against a stored hash using constant-time comparison."""
    try:
        algorithm, iter_str, salt_b64, expected_digest_b64 = stored_hash.split("$", maxsplit=3)
        if algorithm != HASH_ALGORITHM_ID:
            return False
        iterations = int(iter_str)
        if iterations < 10_000:
            return False
        salt_bytes = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
        expected_digest = base64.urlsafe_b64decode(expected_digest_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    material = _derive_key_material(raw_key, pepper)
    actual_digest = hashlib.pbkdf2_hmac("sha256", material, salt_bytes, iterations)
    return hmac.compare_digest(actual_digest, expected_digest)


def dummy_verify_api_key(*, iterations: int = 200_000, pepper: str | None = None) -> None:
    """Perform fixed-cost PBKDF2 work on missing key_id lookups to reduce timing side-channels."""
    material = _derive_key_material("axly_ag_0000000000000000_dummy", pepper)
    hashlib.pbkdf2_hmac("sha256", material, b"chaperone_dummy_s", iterations)


def verify_admin_key(presented_key: str, configured_key: str) -> bool:
    """Verify an admin key using fixed-length SHA-256 digests and constant-time comparison."""
    if not presented_key or not configured_key:
        return False
    presented_digest = hashlib.sha256(presented_key.encode("utf-8")).digest()
    configured_digest = hashlib.sha256(configured_key.encode("utf-8")).digest()
    return hmac.compare_digest(presented_digest, configured_digest)


def generate_admin_bootstrap_key() -> str:
    """Generate a high-entropy random secret suitable for CHAPERONE_ADMIN_API_KEY."""
    return f"axly_adm_{secrets.token_urlsafe(36)}"


def hash_password(
    password: str,
    *,
    iterations: int = 200_000,
    pepper: str | None = None,
) -> str:
    """Hash an administrator password with per-user salt via PBKDF2-HMAC-SHA256."""
    return hash_api_key(password, iterations=iterations, pepper=pepper)


def verify_password(password: str, stored_hash: str, *, pepper: str | None = None) -> bool:
    """Verify an administrator password in constant time."""
    if not password or not stored_hash:
        return False
    return verify_api_key(password, stored_hash, pepper=pepper)


def dummy_verify_password(*, iterations: int = 200_000, pepper: str | None = None) -> None:
    """Balance authentication timing when an admin username does not exist."""
    dummy_verify_api_key(iterations=iterations, pepper=pepper)


def generate_session_token() -> str:
    """Generate a high-entropy opaque cookie session token."""
    return secrets.token_urlsafe(32)


def hash_session_token(raw_token: str) -> str:
    """Hash an opaque session token with SHA-256 for DB storage (never store raw tokens)."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generate a random CSRF synchronizer token bound to the server session."""
    return secrets.token_urlsafe(32)

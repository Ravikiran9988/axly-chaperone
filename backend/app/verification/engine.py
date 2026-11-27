"""Independent post-execution state verification engine (never trusts adapter claims)."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterSecurityError, AdapterValidationError
from app.adapters.file_adapter import (
    list_sandbox_dir_verified,
    read_sandbox_file_verified,
    resolve_sandbox_target,
)
from app.core.config import Settings
from app.models.enums import VerificationOutcome
from app.models.mock_state import DemoInvoice, DemoTask, MockEmailRecord
from app.verification.models import VerificationRecord


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured independent verification result returned and persisted."""

    verification_id: UUID
    status: VerificationOutcome
    method: str
    message: str
    expected_outcome: dict[str, Any]
    observed_outcome: dict[str, Any]


def _normalize_entries_signature(entries: Any) -> list[dict[str, Any]] | None:
    if not isinstance(entries, list):
        return None
    normalized: list[dict[str, Any]] = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            return None
        normalized.append(
            {
                "name": str(item["name"]),
                "type": str(item.get("type", "")),
                "size_bytes": item.get("size_bytes"),
            }
        )
    normalized.sort(key=lambda entry: entry["name"])
    return normalized


def _digest_entries(entries: list[dict[str, Any]]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class VerificationEngine:
    """Independently inspects sandbox filesystem and database state to verify outcomes."""

    async def verify_and_record(
        self,
        session: AsyncSession,
        *,
        correlation_id: str,
        tool_name: str,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        execution_succeeded: bool,
        execution_metadata: dict[str, Any],
        settings: Settings,
        execution_output: dict[str, Any] | None = None,
        audit_event_id: UUID | None = None,
        approval_id: UUID | None = None,
        expected_override: dict[str, Any] | None = None,
    ) -> VerificationResult:
        """Independently inspect system state, compare with expected outcome, and persist record."""
        if not execution_succeeded:
            status = VerificationOutcome.FAILED
            method = "execution_precondition_check"
            expected = expected_override or {"executed": True}
            observed = {"executed": False}
            message = "Execution did not succeed; expected state change could not be confirmed."
        elif tool_name == "file_tool":
            status, method, expected, observed, message = self._verify_file_state(
                action=action,
                resource=resource,
                arguments=arguments,
                execution_metadata=execution_metadata,
                execution_output=execution_output,
                settings=settings,
                expected_override=expected_override,
            )
        elif tool_name == "email_tool":
            status, method, expected, observed, message = await self._verify_email_state(
                session=session,
                action=action,
                resource=resource,
                arguments=arguments,
                correlation_id=correlation_id,
                execution_metadata=execution_metadata,
                expected_override=expected_override,
            )
        elif tool_name == "database_tool":
            status, method, expected, observed, message = await self._verify_database_state(
                session=session,
                action=action,
                resource=resource,
                arguments=arguments,
                execution_metadata=execution_metadata,
                expected_override=expected_override,
            )
        else:
            status = VerificationOutcome.NOT_APPLICABLE
            method = "no_verifier_registered"
            expected = {}
            observed = {}
            message = f"No state verifier defined for tool '{tool_name}'."

        record = VerificationRecord(
            correlation_id=correlation_id,
            audit_event_id=audit_event_id,
            approval_id=approval_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            status=status.value,
            verification_method=method,
            expected_outcome=expected,
            observed_outcome=observed,
            message=message,
        )
        session.add(record)
        await session.flush()

        return VerificationResult(
            verification_id=record.id,
            status=status,
            method=method,
            message=message,
            expected_outcome=expected,
            observed_outcome=observed,
        )

    def _verify_file_state(
        self,
        *,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        execution_metadata: dict[str, Any],
        execution_output: dict[str, Any] | None,
        settings: Settings,
        expected_override: dict[str, Any] | None,
    ) -> tuple[VerificationOutcome, str, dict[str, Any], dict[str, Any], str]:
        sandbox_root = Path(settings.sandbox_dir)
        try:
            resolve_sandbox_target(sandbox_root, resource)
        except (AdapterSecurityError, ValueError):
            return (
                VerificationOutcome.FAILED,
                "sandbox_path_verification",
                {"in_sandbox": True, "path": resource},
                {"in_sandbox": False},
                "Target path could not be resolved inside sandbox.",
            )

        if action == "write":
            raw_content = arguments.get("content", "")
            expected_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else b""
            expected = expected_override or {
                "exists": True,
                "is_file": True,
                "content_sha256": hashlib.sha256(expected_bytes).hexdigest(),
                "size_bytes": len(expected_bytes),
            }
            try:
                actual_bytes, actual_digest = read_sandbox_file_verified(
                    sandbox_root,
                    resource,
                    max_bytes=settings.max_file_size_bytes,
                )
            except FileNotFoundError:
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_hash_check",
                    expected,
                    {"exists": False},
                    "Expected written file does not exist as a regular file inside sandbox.",
                )
            except (AdapterSecurityError, AdapterValidationError):
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_hash_check",
                    expected,
                    {"exists": False},
                    "Target file failed security handle check during independent verification.",
                )
            except OSError:
                return (
                    VerificationOutcome.INCONCLUSIVE,
                    "sandbox_file_hash_check",
                    expected,
                    {"readable": False},
                    "Could not read sandbox file during independent verification.",
                )
            observed = {
                "exists": True,
                "is_file": True,
                "content_sha256": actual_digest,
                "size_bytes": len(actual_bytes),
            }
            if observed == expected:
                return (
                    VerificationOutcome.VERIFIED,
                    "sandbox_file_hash_check",
                    expected,
                    observed,
                    "File existence, byte length, and SHA-256 content hash independently verified.",
                )
            return (
                VerificationOutcome.FAILED,
                "sandbox_file_hash_check",
                expected,
                observed,
                "Observed file state did not match expected SHA-256 hash or size.",
            )

        if action == "read":
            try:
                actual_bytes, actual_digest = read_sandbox_file_verified(
                    sandbox_root,
                    resource,
                    max_bytes=settings.max_file_size_bytes,
                )
            except FileNotFoundError:
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_read_digest_check",
                    expected_override or {"exists": True, "is_file": True},
                    {"exists": False, "is_file": False},
                    "Read target could not be confirmed inside sandbox.",
                )
            except (AdapterSecurityError, AdapterValidationError):
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_read_digest_check",
                    expected_override or {"exists": True, "is_file": True},
                    {"exists": False, "is_file": False},
                    "Read target failed security handle check during verification.",
                )
            except OSError:
                return (
                    VerificationOutcome.INCONCLUSIVE,
                    "sandbox_file_read_digest_check",
                    expected_override or {"exists": True, "is_file": True},
                    {"readable": False},
                    "Could not independently reopen read target inside sandbox.",
                )

            if expected_override is not None:
                observed_basic = {"exists": True, "is_file": True}
                matched = observed_basic == expected_override
                return (
                    VerificationOutcome.VERIFIED if matched else VerificationOutcome.FAILED,
                    "sandbox_file_read_digest_check",
                    expected_override,
                    observed_basic,
                    "Read target independently confirmed inside sandbox."
                    if matched
                    else "Read verification failed against expected condition.",
                )

            if execution_output is None:
                return (
                    VerificationOutcome.INCONCLUSIVE,
                    "sandbox_file_read_digest_check",
                    {"path": resource, "has_output": True},
                    {"path": resource, "has_output": False},
                    "Adapter output unavailable; read content could not be verified.",
                )

            observed = {
                "exists": True,
                "is_file": True,
                "path": resource,
                "content_sha256": actual_digest,
                "size_bytes": len(actual_bytes),
            }
            claimed_content = execution_output.get("content")
            if not isinstance(claimed_content, str):
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_read_digest_check",
                    {"exists": True, "is_file": True, "path": resource, "has_content": True},
                    observed,
                    "Adapter read response omitted text content for verification.",
                )

            # Compare UTF-8 normalized bytes if valid UTF-8 or fallback decoded text consistently
            disk_decoded_bytes = actual_bytes.decode("utf-8", errors="replace").encode("utf-8")
            claimed_bytes = claimed_content.encode("utf-8")
            claimed_digest = hashlib.sha256(claimed_bytes).hexdigest()
            disk_decoded_digest = hashlib.sha256(disk_decoded_bytes).hexdigest()
            claimed_size = execution_output.get("size_bytes", len(claimed_bytes))
            meta_digest = execution_metadata.get("content_sha256")
            claimed_evidence = {
                "exists": True,
                "is_file": True,
                "path": str(execution_output.get("path", resource)),
                "content_sha256": claimed_digest,
                "size_bytes": claimed_size,
            }
            matches = (
                (claimed_digest == actual_digest or claimed_digest == disk_decoded_digest)
                and claimed_size == len(actual_bytes)
                and (meta_digest is None or meta_digest == actual_digest)
                and str(execution_output.get("path", resource)) == resource
            )
            if matches:
                return (
                    VerificationOutcome.VERIFIED,
                    "sandbox_file_read_digest_check",
                    claimed_evidence,
                    observed,
                    "Read file content SHA-256 digest and byte length independently verified.",
                )
            return (
                VerificationOutcome.FAILED,
                "sandbox_file_read_digest_check",
                claimed_evidence,
                observed,
                "Adapter read output did not match actual sandbox file SHA-256 digest or length.",
            )

        # list action: independently inspect directory entries and compare names, types, sizes
        try:
            actual_entries = list_sandbox_dir_verified(sandbox_root, resource)
        except FileNotFoundError:
            return (
                VerificationOutcome.FAILED,
                "sandbox_directory_entries_check",
                expected_override or {"exists": True, "is_dir": True},
                {"exists": False, "is_dir": False},
                "Directory missing inside sandbox.",
            )
        except (AdapterSecurityError, AdapterValidationError):
            return (
                VerificationOutcome.FAILED,
                "sandbox_directory_entries_check",
                expected_override or {"exists": True, "is_dir": True},
                {"exists": False, "is_dir": False},
                "Directory failed security handle check during verification.",
            )
        except OSError:
            return (
                VerificationOutcome.INCONCLUSIVE,
                "sandbox_directory_entries_check",
                expected_override or {"exists": True, "is_dir": True},
                {"readable": False},
                "Could not independently inspect sandbox directory.",
            )

        if expected_override is not None:
            observed_dir = {"exists": True, "is_dir": True}
            matched = observed_dir == expected_override
            return (
                VerificationOutcome.VERIFIED if matched else VerificationOutcome.FAILED,
                "sandbox_directory_entries_check",
                expected_override,
                observed_dir,
                "Sandbox directory verified."
                if matched
                else "Directory failed expected override check.",
            )

        if execution_output is None:
            return (
                VerificationOutcome.INCONCLUSIVE,
                "sandbox_directory_entries_check",
                {"directory": resource, "has_output": True},
                {"directory": resource, "has_output": False},
                "Adapter output unavailable; directory listing could not be verified.",
            )

        actual_sig = _normalize_entries_signature(actual_entries) or []
        observed_summary = {
            "directory": resource,
            "entry_count": len(actual_sig),
            "entries_sha256": _digest_entries(actual_sig),
            "entry_names": [item["name"] for item in actual_sig[:50]],
        }
        claimed_sig = _normalize_entries_signature(execution_output.get("entries"))
        if claimed_sig is None:
            return (
                VerificationOutcome.FAILED,
                "sandbox_directory_entries_check",
                {"directory": str(execution_output.get("directory", resource)), "entries": None},
                observed_summary,
                "Adapter directory response omitted valid entry list.",
            )

        claimed_summary = {
            "directory": str(execution_output.get("directory", resource)),
            "entry_count": len(claimed_sig),
            "entries_sha256": _digest_entries(claimed_sig),
            "entry_names": [item["name"] for item in claimed_sig[:50]],
        }
        if claimed_summary == observed_summary and claimed_sig == actual_sig:
            return (
                VerificationOutcome.VERIFIED,
                "sandbox_directory_entries_check",
                claimed_summary,
                observed_summary,
                "Sandbox directory entry names, types, sizes, and digest independently verified.",
            )
        return (
            VerificationOutcome.FAILED,
            "sandbox_directory_entries_check",
            claimed_summary,
            observed_summary,
            "Adapter directory listing did not match actual sandbox directory entries.",
        )

    async def _verify_email_state(
        self,
        *,
        session: AsyncSession,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        correlation_id: str,
        execution_metadata: dict[str, Any],
        expected_override: dict[str, Any] | None,
    ) -> tuple[VerificationOutcome, str, dict[str, Any], dict[str, Any], str]:
        if action == "read":
            if expected_override is None:
                return (
                    VerificationOutcome.NOT_APPLICABLE,
                    "mock_email_read_only",
                    {"mutates_state": False},
                    {"mutates_state": False},
                    "Read-only mock email query required no state-change verification.",
                )
            return (
                VerificationOutcome.FAILED,
                "mock_email_read_only",
                expected_override,
                {"mutates_state": False},
                "Expected state change mismatch for read-only email query.",
            )

        expected_status = "sent" if action == "send" else "draft"
        expected = expected_override or {
            "recipient": resource,
            "subject": str(arguments.get("subject", "")).strip(),
            "status": expected_status,
        }

        email_id_str = execution_metadata.get("email_id")
        stmt = select(MockEmailRecord)
        if email_id_str:
            try:
                stmt = stmt.where(MockEmailRecord.id == uuid.UUID(str(email_id_str)))
            except ValueError:
                stmt = stmt.where(MockEmailRecord.correlation_id == correlation_id)
        else:
            stmt = stmt.where(
                MockEmailRecord.correlation_id == correlation_id,
                MockEmailRecord.recipient == resource,
            )

        record = (await session.execute(stmt)).scalar_one_or_none()
        if record is None:
            return (
                VerificationOutcome.FAILED,
                "mock_email_db_query",
                expected,
                {"found": False},
                "Mock email record was not found in provider storage.",
            )

        observed = {
            "recipient": record.recipient,
            "subject": record.subject,
            "status": record.status,
        }
        if observed == expected:
            return (
                VerificationOutcome.VERIFIED,
                "mock_email_db_query",
                expected,
                observed,
                "Mock email recipient, subject, and delivery status independently verified.",
            )
        return (
            VerificationOutcome.FAILED,
            "mock_email_db_query",
            expected,
            observed,
            "Observed mock email state did not match expected recipient, subject, or status.",
        )

    async def _verify_database_state(
        self,
        *,
        session: AsyncSession,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        execution_metadata: dict[str, Any],
        expected_override: dict[str, Any] | None,
    ) -> tuple[VerificationOutcome, str, dict[str, Any], dict[str, Any], str]:
        if action == "read":
            if expected_override is None:
                return (
                    VerificationOutcome.NOT_APPLICABLE,
                    "demo_db_read_only",
                    {"mutates_state": False},
                    {"mutates_state": False},
                    "Read-only database query required no state-change verification.",
                )
            return (
                VerificationOutcome.FAILED,
                "demo_db_read_only",
                expected_override,
                {"mutates_state": False},
                "Expected state change mismatch for read-only database query.",
            )

        record_id_str = execution_metadata.get("record_id") or arguments.get("record_id")
        expected_fields = expected_override or execution_metadata.get(
            "expected_fields", arguments.get("data", {})
        )
        if not record_id_str:
            return (
                VerificationOutcome.INCONCLUSIVE,
                "demo_db_record_query",
                expected_fields,
                {"record_id": None},
                "Record identifier unavailable for independent DB verification.",
            )

        try:
            row_uuid = uuid.UUID(str(record_id_str))
        except ValueError:
            return (
                VerificationOutcome.FAILED,
                "demo_db_record_query",
                expected_fields,
                {"invalid_record_id": True},
                "Invalid record UUID for independent DB verification.",
            )

        model = DemoInvoice if resource == "demo_invoices" else DemoTask
        row = (
            await session.execute(select(model).where(model.id == row_uuid))
        ).scalar_one_or_none()
        if row is None:
            return (
                VerificationOutcome.FAILED,
                "demo_db_record_query",
                expected_fields,
                {"found": False},
                "Target database record was not found after mutation.",
            )

        observed = {col: getattr(row, col, None) for col in expected_fields}
        if observed == expected_fields:
            return (
                VerificationOutcome.VERIFIED,
                "demo_db_record_query",
                expected_fields,
                observed,
                "Database record existence and field values independently verified.",
            )
        return (
            VerificationOutcome.FAILED,
            "demo_db_record_query",
            expected_fields,
            observed,
            "Observed database record fields did not match expected values.",
        )

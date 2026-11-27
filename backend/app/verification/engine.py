"""Independent post-execution state verification engine (never trusts adapter claims)."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterSecurityError
from app.adapters.file_adapter import resolve_sandbox_target
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
        settings: Settings,
        expected_override: dict[str, Any] | None,
    ) -> tuple[VerificationOutcome, str, dict[str, Any], dict[str, Any], str]:
        sandbox_root = Path(settings.sandbox_dir)
        try:
            target = resolve_sandbox_target(sandbox_root, resource)
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
            if not target.exists() or os.path.islink(target) or not target.is_file():
                return (
                    VerificationOutcome.FAILED,
                    "sandbox_file_hash_check",
                    expected,
                    {"exists": False},
                    "Expected written file does not exist as a regular file inside sandbox.",
                )
            try:
                actual_bytes = target.read_bytes()
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
                "content_sha256": hashlib.sha256(actual_bytes).hexdigest(),
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
            expected = expected_override or {"exists": True, "is_file": True}
            exists = target.exists() and not os.path.islink(target) and target.is_file()
            observed = {"exists": exists, "is_file": exists}
            if observed == expected:
                return (
                    VerificationOutcome.VERIFIED,
                    "sandbox_file_presence_check",
                    expected,
                    observed,
                    "Read target independently confirmed inside sandbox.",
                )
            return (
                VerificationOutcome.FAILED,
                "sandbox_file_presence_check",
                expected,
                observed,
                "Read target could not be confirmed inside sandbox.",
            )

        # list action
        expected = expected_override or {"exists": True, "is_dir": True}
        is_dir = target.exists() and not os.path.islink(target) and target.is_dir()
        observed = {"exists": is_dir, "is_dir": is_dir}
        status = (
            VerificationOutcome.VERIFIED if observed == expected else VerificationOutcome.FAILED
        )
        return (
            status,
            "sandbox_directory_presence_check",
            expected,
            observed,
            "Sandbox directory verified."
            if status == VerificationOutcome.VERIFIED
            else "Directory missing.",
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

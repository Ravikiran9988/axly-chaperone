"""Mock email tool adapter persisted locally (never connects to an external mail provider)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.adapters.base import (
    AdapterExecutionResult,
    AdapterSecurityError,
    AdapterValidationError,
    BaseToolAdapter,
    ExecutionContext,
)
from app.core.config import Settings
from app.models.mock_state import MockEmailRecord
from app.security.resource_validator import normalize_communication_resource


class EmailToolAdapter(BaseToolAdapter):
    """Controlled mock email provider supporting create_draft, send, and read."""

    tool_name = "email_tool"
    category = "communication"
    supported_actions = frozenset({"create_draft", "send", "read"})

    def validate_resource(self, action: str, resource: str, arguments: dict[str, Any]) -> str:
        if action not in self.supported_actions:
            raise AdapterValidationError(f"Unsupported email_tool action '{action}'.")
        try:
            canonical = normalize_communication_resource(resource)
        except ValueError as exc:
            raise AdapterSecurityError(str(exc)) from exc

        if action in {"create_draft", "send"} and "@" not in canonical:
            raise AdapterValidationError(
                f"Email action '{action}' requires a valid recipient email address resource."
            )
        return canonical

    def validate_inputs(
        self,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        *,
        settings: Settings,
    ) -> dict[str, Any]:
        if action not in self.supported_actions:
            raise AdapterValidationError(f"Unsupported email_tool action '{action}'.")

        if action in {"create_draft", "send"}:
            subject = arguments.get("subject")
            body = arguments.get("body")
            if not isinstance(subject, str) or not subject.strip() or len(subject) > 256:
                raise AdapterValidationError("Email requires a non-empty 'subject' (<= 256 chars).")
            if "\r" in subject or "\n" in subject:
                raise AdapterValidationError("Email subject cannot contain newline characters.")
            if not isinstance(body, str) or not body.strip():
                raise AdapterValidationError("Email requires a non-empty string 'body'.")
            if len(body.encode("utf-8")) > settings.max_argument_payload_bytes:
                raise AdapterValidationError("Email body exceeds configured payload size limit.")
            return {
                "to": resource,
                "subject": subject.strip(),
                "body": body,
            }

        limit = arguments.get("limit", 20)
        if not isinstance(limit, int) or limit < 1 or limit > 50:
            raise AdapterValidationError("Email read 'limit' must be an integer between 1 and 50.")
        return {"target": resource, "limit": limit}

    async def execute(self, context: ExecutionContext) -> AdapterExecutionResult:
        canonical = self.validate_resource(context.action, context.resource, context.arguments)

        if context.action in {"create_draft", "send"}:
            subject = str(context.arguments["subject"]).strip()
            body = str(context.arguments["body"])
            target_status = "draft" if context.action == "create_draft" else "sent"

            draft_id_raw = context.arguments.get("draft_id")
            record: MockEmailRecord | None = None
            if draft_id_raw is not None and context.action == "send":
                try:
                    draft_uuid = uuid.UUID(str(draft_id_raw))
                except ValueError as exc:
                    raise AdapterValidationError("Invalid draft_id UUID.") from exc
                stmt = select(MockEmailRecord).where(MockEmailRecord.id == draft_uuid)
                record = (await context.session.execute(stmt)).scalar_one_or_none()
                if record is None or record.recipient != canonical or record.status != "draft":
                    raise AdapterValidationError("Matching draft email was not found.")
                record.subject = subject
                record.body = body
                record.status = target_status
                record.correlation_id = context.correlation_id
                record.approval_id = context.approval_id
            else:
                record = MockEmailRecord(
                    correlation_id=context.correlation_id,
                    recipient=canonical,
                    subject=subject,
                    body=body,
                    status=target_status,
                    approval_id=context.approval_id,
                )
                context.session.add(record)

            await context.session.flush()
            return AdapterExecutionResult(
                success=True,
                summary=f"Mock email {target_status} recorded for '{canonical}'.",
                output={
                    "email_id": str(record.id),
                    "recipient": record.recipient,
                    "subject": record.subject,
                    "status": record.status,
                },
                metadata={
                    "email_id": str(record.id),
                    "recipient": record.recipient,
                    "subject": record.subject,
                    "delivery_status": record.status,
                },
            )

        # read action
        limit = int(context.arguments.get("limit", 20))
        stmt = select(MockEmailRecord).order_by(MockEmailRecord.created_at.desc()).limit(limit)
        if canonical == "sent":
            stmt = stmt.where(MockEmailRecord.status == "sent")
        elif canonical == "drafts":
            stmt = stmt.where(MockEmailRecord.status == "draft")
        elif "@" in canonical:
            stmt = stmt.where(MockEmailRecord.recipient == canonical)

        rows = (await context.session.execute(stmt)).scalars().all()
        items = [
            {
                "email_id": str(row.id),
                "recipient": row.recipient,
                "subject": row.subject,
                "status": row.status,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]
        return AdapterExecutionResult(
            success=True,
            summary=f"Read {len(items)} mock email record(s).",
            output={"records": items, "count": len(items)},
            metadata={"record_count": len(items), "scope": canonical},
        )

"""Structured parameterized database tool adapter restricted to approved demo tables."""

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
from app.models.mock_state import DemoInvoice, DemoTask
from app.security.resource_validator import normalize_database_resource

APPROVED_TABLES = frozenset({"demo_invoices", "demo_tasks"})
_RAW_SQL_KEYS = frozenset({"sql", "query", "raw_sql", "statement", "command"})

_TABLE_SPECS: dict[str, dict[str, Any]] = {
    "demo_invoices": {
        "model": DemoInvoice,
        "columns": frozenset({"invoice_number", "vendor_name", "amount_inr", "status", "notes"}),
        "required_on_create": frozenset({"invoice_number", "vendor_name", "amount_inr"}),
        "string_max_lengths": {
            "invoice_number": 64,
            "vendor_name": 128,
            "status": 32,
            "notes": 2000,
        },
        "nullable_columns": frozenset({"notes"}),
    },
    "demo_tasks": {
        "model": DemoTask,
        "columns": frozenset({"title", "owner", "status"}),
        "required_on_create": frozenset({"title", "owner"}),
        "string_max_lengths": {
            "title": 200,
            "owner": 128,
            "status": 32,
        },
        "nullable_columns": frozenset(),
    },
}


def _validate_column_value(spec: dict[str, Any], col: str, val: Any) -> Any:
    if col == "amount_inr":
        if isinstance(val, bool) or not isinstance(val, int) or val < 0 or val > 2_147_483_647:
            raise AdapterValidationError(
                "'amount_inr' must be a non-negative 32-bit integer (booleans rejected)."
            )
        return val
    if val is None:
        if col not in spec["nullable_columns"]:
            raise AdapterValidationError(f"Column '{col}' cannot be null.")
        return None
    if not isinstance(val, str):
        raise AdapterValidationError(f"Column '{col}' must be a string.")
    cleaned = val.strip()
    max_len = spec["string_max_lengths"][col]
    if not cleaned and col not in spec["nullable_columns"]:
        raise AdapterValidationError(f"Column '{col}' cannot be empty.")
    if len(cleaned) > max_len:
        raise AdapterValidationError(f"Column '{col}' exceeds maximum length of {max_len}.")
    return cleaned if cleaned or col not in spec["nullable_columns"] else None


class DatabaseToolAdapter(BaseToolAdapter):
    """Controlled database adapter permitting structured CRUD on approved demo tables only."""

    tool_name = "database_tool"
    category = "database"
    supported_actions = frozenset({"read", "create", "update"})

    def validate_resource(self, action: str, resource: str, arguments: dict[str, Any]) -> str:
        if action not in self.supported_actions:
            raise AdapterValidationError(f"Unsupported database_tool action '{action}'.")
        try:
            canonical = normalize_database_resource(resource)
        except ValueError as exc:
            raise AdapterSecurityError(str(exc)) from exc
        if canonical not in APPROVED_TABLES:
            raise AdapterSecurityError(
                f"Table '{canonical}' is not in the approved database table allowlist."
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
            raise AdapterValidationError(f"Unsupported database_tool action '{action}'.")
        for arg_key in arguments:
            if str(arg_key).lower() in _RAW_SQL_KEYS:
                raise AdapterSecurityError(f"Arbitrary SQL parameter '{arg_key}' is prohibited.")

        spec = _TABLE_SPECS[resource]
        allowed_cols: frozenset[str] = spec["columns"]

        if action == "read":
            filters = arguments.get("filters", {})
            if not isinstance(filters, dict):
                raise AdapterValidationError("'filters' must be a JSON object.")
            for col, val in filters.items():
                if col not in allowed_cols:
                    raise AdapterValidationError(
                        f"Column '{col}' is not permitted for '{resource}'."
                    )
                _validate_column_value(spec, col, val)
            limit = arguments.get("limit", 20)
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > 50:
                raise AdapterValidationError("'limit' must be an integer between 1 and 50.")
            return {"table": resource, "filters": filters, "limit": limit}

        data = arguments.get("data")
        if not isinstance(data, dict) or not data:
            raise AdapterValidationError(f"Action '{action}' requires a non-empty 'data' object.")
        for col, val in data.items():
            if col not in allowed_cols:
                raise AdapterValidationError(f"Column '{col}' is not permitted for '{resource}'.")
            _validate_column_value(spec, col, val)

        if action == "create":
            missing = spec["required_on_create"] - set(data.keys())
            if missing:
                raise AdapterValidationError(
                    f"Missing required column(s) for '{resource}': {sorted(missing)}"
                )
            return {"table": resource, "data": data}

        record_id = arguments.get("record_id")
        invoice_number = arguments.get("invoice_number")
        if record_id is None and invoice_number is None:
            raise AdapterValidationError("Update requires 'record_id' (UUID) or 'invoice_number'.")
        return {
            "table": resource,
            "record_id": str(record_id) if record_id is not None else None,
            "invoice_number": str(invoice_number) if invoice_number is not None else None,
            "data": data,
        }

    async def execute(self, context: ExecutionContext) -> AdapterExecutionResult:
        table = self.validate_resource(context.action, context.resource, context.arguments)
        self.validate_inputs(context.action, table, context.arguments, settings=context.settings)

        if table == "demo_invoices":
            return await self._execute_invoice(context)
        return await self._execute_task(context)

    async def _execute_invoice(self, context: ExecutionContext) -> AdapterExecutionResult:
        if context.action == "read":
            filters: dict[str, Any] = context.arguments.get("filters", {})
            limit = int(context.arguments.get("limit", 20))
            stmt = select(DemoInvoice)
            for col, val in filters.items():
                stmt = stmt.where(getattr(DemoInvoice, col) == val)
            stmt = stmt.order_by(DemoInvoice.created_at.desc()).limit(limit)
            rows = (await context.session.execute(stmt)).scalars().all()
            records = [
                {
                    "id": str(r.id),
                    "invoice_number": r.invoice_number,
                    "vendor_name": r.vendor_name,
                    "amount_inr": r.amount_inr,
                    "status": r.status,
                    "notes": r.notes,
                }
                for r in rows
            ]
            return AdapterExecutionResult(
                success=True,
                summary=f"Read {len(records)} row(s) from demo_invoices.",
                output={"table": "demo_invoices", "records": records, "count": len(records)},
                metadata={"table": "demo_invoices", "record_count": len(records)},
            )

        if context.action == "create":
            data = context.arguments["data"]
            amount = data["amount_inr"]
            if not isinstance(amount, int) or amount < 0:
                raise AdapterValidationError("'amount_inr' must be a non-negative integer.")
            row = DemoInvoice(
                invoice_number=str(data["invoice_number"]).strip(),
                vendor_name=str(data["vendor_name"]).strip(),
                amount_inr=amount,
                status=str(data.get("status", "pending")).strip(),
                notes=str(data["notes"]).strip() if data.get("notes") is not None else None,
            )
            context.session.add(row)
            await context.session.flush()
            return AdapterExecutionResult(
                success=True,
                summary=f"Created demo_invoices record '{row.invoice_number}'.",
                output={
                    "table": "demo_invoices",
                    "record_id": str(row.id),
                    "invoice_number": row.invoice_number,
                    "vendor_name": row.vendor_name,
                    "amount_inr": row.amount_inr,
                    "status": row.status,
                },
                metadata={
                    "table": "demo_invoices",
                    "record_id": str(row.id),
                    "expected_fields": {
                        "invoice_number": row.invoice_number,
                        "vendor_name": row.vendor_name,
                        "amount_inr": row.amount_inr,
                        "status": row.status,
                    },
                },
            )

        # update action
        record_id = context.arguments.get("record_id")
        invoice_number = context.arguments.get("invoice_number")
        stmt = select(DemoInvoice)
        if record_id is not None:
            try:
                stmt = stmt.where(DemoInvoice.id == uuid.UUID(str(record_id)))
            except ValueError as exc:
                raise AdapterValidationError("Invalid 'record_id' UUID.") from exc
        else:
            stmt = stmt.where(DemoInvoice.invoice_number == str(invoice_number))
        row = (await context.session.execute(stmt)).scalar_one_or_none()
        if row is None:
            return AdapterExecutionResult(
                success=False,
                summary="Target demo_invoices record not found.",
                error_message="Target record not found.",
            )
        data = context.arguments["data"]
        updated_fields: dict[str, Any] = {}
        for col, val in data.items():
            if col == "amount_inr" and (not isinstance(val, int) or val < 0):
                raise AdapterValidationError("'amount_inr' must be a non-negative integer.")
            setattr(row, col, val)
            updated_fields[col] = val
        await context.session.flush()
        return AdapterExecutionResult(
            success=True,
            summary=f"Updated demo_invoices record '{row.id}'.",
            output={"table": "demo_invoices", "record_id": str(row.id), "updated": updated_fields},
            metadata={
                "table": "demo_invoices",
                "record_id": str(row.id),
                "expected_fields": updated_fields,
            },
        )

    async def _execute_task(self, context: ExecutionContext) -> AdapterExecutionResult:
        if context.action == "read":
            filters: dict[str, Any] = context.arguments.get("filters", {})
            limit = int(context.arguments.get("limit", 20))
            stmt = select(DemoTask)
            for col, val in filters.items():
                stmt = stmt.where(getattr(DemoTask, col) == val)
            stmt = stmt.order_by(DemoTask.created_at.desc()).limit(limit)
            rows = (await context.session.execute(stmt)).scalars().all()
            records = [
                {
                    "id": str(r.id),
                    "title": r.title,
                    "owner": r.owner,
                    "status": r.status,
                }
                for r in rows
            ]
            return AdapterExecutionResult(
                success=True,
                summary=f"Read {len(records)} row(s) from demo_tasks.",
                output={"table": "demo_tasks", "records": records, "count": len(records)},
                metadata={"table": "demo_tasks", "record_count": len(records)},
            )

        if context.action == "create":
            data = context.arguments["data"]
            row = DemoTask(
                title=str(data["title"]).strip(),
                owner=str(data["owner"]).strip(),
                status=str(data.get("status", "open")).strip(),
            )
            context.session.add(row)
            await context.session.flush()
            return AdapterExecutionResult(
                success=True,
                summary=f"Created demo_tasks record '{row.id}'.",
                output={
                    "table": "demo_tasks",
                    "record_id": str(row.id),
                    "title": row.title,
                    "owner": row.owner,
                    "status": row.status,
                },
                metadata={
                    "table": "demo_tasks",
                    "record_id": str(row.id),
                    "expected_fields": {
                        "title": row.title,
                        "owner": row.owner,
                        "status": row.status,
                    },
                },
            )

        record_id = context.arguments.get("record_id")
        if record_id is None:
            raise AdapterValidationError("Updating demo_tasks requires 'record_id'.")
        try:
            row_uuid = uuid.UUID(str(record_id))
        except ValueError as exc:
            raise AdapterValidationError("Invalid 'record_id' UUID.") from exc
        row = (
            await context.session.execute(select(DemoTask).where(DemoTask.id == row_uuid))
        ).scalar_one_or_none()
        if row is None:
            return AdapterExecutionResult(
                success=False,
                summary="Target demo_tasks record not found.",
                error_message="Target record not found.",
            )
        data = context.arguments["data"]
        updated_fields: dict[str, Any] = {}
        for col, val in data.items():
            setattr(row, col, val)
            updated_fields[col] = val
        await context.session.flush()
        return AdapterExecutionResult(
            success=True,
            summary=f"Updated demo_tasks record '{row.id}'.",
            output={"table": "demo_tasks", "record_id": str(row.id), "updated": updated_fields},
            metadata={
                "table": "demo_tasks",
                "record_id": str(row.id),
                "expected_fields": updated_fields,
            },
        )

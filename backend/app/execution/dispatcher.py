"""Controlled tool dispatcher enforcing registry, validation, and execution timeouts."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.base import AdapterSecurityError, AdapterValidationError, ExecutionContext
from app.core.config import Settings
from app.execution.models import DispatchResult
from app.execution.registry import AdapterRegistry
from app.models.enums import ExecutionStatus
from app.models.tool import Tool

logger = logging.getLogger("chaperone.execution")


class ExecutionDispatcher:
    """Dispatches authorized tool requests strictly to registered and enabled adapters."""

    def __init__(self, registry: AdapterRegistry | None = None) -> None:
        self._registry = registry or AdapterRegistry()

    def get_registry(self) -> AdapterRegistry:
        """Return underlying adapter registry."""
        return self._registry

    async def dispatch(
        self,
        session: AsyncSession,
        *,
        correlation_id: str,
        agent_id: UUID,
        tool_name: str,
        action: str,
        resource: str,
        arguments: dict[str, Any],
        settings: Settings,
        approval_id: UUID | None = None,
    ) -> DispatchResult:
        """Validate DB registration, adapter safety rules, and execute with timeout."""
        tool_row = (
            await session.execute(select(Tool).where(Tool.name == tool_name))
        ).scalar_one_or_none()
        if tool_row is None or not tool_row.enabled:
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary=f"Tool '{tool_name}' is not registered or is disabled.",
                error_message="Tool unavailable for execution.",
            )

        adapter = self._registry.get(tool_name)
        if adapter is None:
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary=f"No execution adapter registered for tool '{tool_name}'.",
                error_message="Execution adapter unavailable.",
            )

        try:
            canonical_resource = adapter.validate_resource(action, resource, arguments)
            adapter.validate_inputs(action, canonical_resource, arguments, settings=settings)
        except (AdapterValidationError, AdapterSecurityError) as exc:
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary="Adapter validation rejected the execution request.",
                error_message=str(exc),
            )

        context = ExecutionContext(
            correlation_id=correlation_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=canonical_resource,
            arguments=arguments,
            session=session,
            settings=settings,
            approval_id=approval_id,
        )

        try:
            adapter_result = await asyncio.wait_for(
                adapter.execute(context),
                timeout=settings.tool_execution_timeout_seconds,
            )
        except TimeoutError:
            logger.warning(
                "Tool adapter execution timed out",
                extra={"correlation_id": correlation_id, "agent_id": str(agent_id)},
            )
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary=f"Tool '{tool_name}' execution timed out.",
                error_message="Tool execution exceeded configured timeout.",
                timed_out=True,
            )
        except (AdapterValidationError, AdapterSecurityError) as exc:
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary="Adapter rejected execution.",
                error_message=str(exc),
            )
        except Exception:
            logger.exception(
                "Unexpected adapter execution failure",
                extra={"correlation_id": correlation_id, "agent_id": str(agent_id)},
            )
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary="Tool execution failed due to an internal adapter error.",
                error_message="Internal adapter execution failure.",
            )

        if not adapter_result.success:
            return DispatchResult(
                status=ExecutionStatus.FAILED,
                summary=adapter_result.summary,
                output=adapter_result.output,
                metadata=adapter_result.metadata,
                error_message=adapter_result.error_message or "Adapter reported failure.",
            )

        return DispatchResult(
            status=ExecutionStatus.EXECUTED,
            summary=adapter_result.summary,
            output=adapter_result.output,
            metadata=adapter_result.metadata,
        )

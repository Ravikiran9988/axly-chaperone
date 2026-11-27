"""MCP server exposing controlled Chaperone tools routed strictly through the gateway."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

import mcp.types as types
from mcp.server.lowlevel.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.adapters.mcp.schemas import (
    McpDatabaseToolInput,
    McpEmailToolInput,
    McpFileToolInput,
    McpToolCallEnvelope,
)
from app.core.config import Settings, get_settings
from app.core.database import build_engine, build_session_factory
from app.core.exceptions import ChaperoneError
from app.core.logging import configure_logging
from app.models.enums import VerificationStatus
from app.schemas.gateway import GatewayExecuteRequest
from app.security.authentication import authenticate_agent_key
from app.services.gateway_service import GatewayService

logger = logging.getLogger("chaperone.mcp")

_TOOL_SCHEMAS: dict[str, tuple[str, type[McpToolCallEnvelope]]] = {
    "file_tool": (
        "Controlled sandbox filesystem tool (actions: read, write, list). "
        "All calls are authenticated, policy-evaluated, and audited by Chaperone.",
        McpFileToolInput,
    ),
    "email_tool": (
        "Controlled mock email tool (actions: create_draft, send, read). "
        "Outbound actions enforce policy and human approval via Chaperone.",
        McpEmailToolInput,
    ),
    "database_tool": (
        "Controlled structured database tool on approved demo tables "
        "(actions: read, create, update). Arbitrary SQL is prohibited.",
        McpDatabaseToolInput,
    ),
}


def _mcp_error_result(
    *,
    code: str,
    message: str,
    correlation_id: str,
) -> types.CallToolResult:
    payload = {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": correlation_id,
        }
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(payload))],
        structured_content=payload,
        is_error=True,
    )


def create_chaperone_mcp_server(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    gateway_service: GatewayService | None = None,
) -> Server[Any]:
    """Create an MCP Server whose tool calls pass strictly through Chaperone's gateway."""
    gateway = gateway_service or GatewayService()

    async def handle_list_tools(
        _ctx: ServerRequestContext[Any],
        _params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        tools = [
            types.Tool(
                name=name,
                description=description,
                input_schema=schema_cls.model_json_schema(),
            )
            for name, (description, schema_cls) in _TOOL_SCHEMAS.items()
        ]
        return types.ListToolsResult(tools=tools)

    async def handle_call_tool(
        _ctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        fallback_cid = str(uuid.uuid4())
        tool_entry = _TOOL_SCHEMAS.get(params.name)
        if tool_entry is None:
            return _mcp_error_result(
                code="UNKNOWN_TOOL",
                message=f"Tool '{params.name}' is not exposed by Chaperone MCP.",
                correlation_id=fallback_cid,
            )

        _, schema_cls = tool_entry
        raw_args = params.arguments if isinstance(params.arguments, dict) else {}

        try:
            validated = schema_cls.model_validate(raw_args)
        except ValidationError as exc:
            first_err = exc.errors()[0].get("msg", "Invalid MCP tool arguments.")
            return _mcp_error_result(
                code="INVALID_MCP_ARGUMENTS",
                message=str(first_err),
                correlation_id=fallback_cid,
            )

        correlation_id = validated.correlation_id or fallback_cid
        default_mcp_key = (
            settings.mcp_agent_key.get_secret_value()
            if settings.mcp_agent_key is not None
            else None
        )
        presented_key = validated.agent_api_key or default_mcp_key

        async with session_factory() as session:
            auth_result = await authenticate_agent_key(
                presented_key,
                session=session,
                settings=settings,
            )
            if not auth_result.authenticated or auth_result.agent is None:
                try:
                    await gateway.record_unauthenticated_attempt(
                        session,
                        auth_result=auth_result,
                        correlation_id=correlation_id,
                        tool_name=params.name,
                        action=validated.action,
                        resource=validated.resource,
                    )
                except ChaperoneError as exc:
                    err_code = (
                        "AGENT_DISABLED"
                        if auth_result.verification_status == VerificationStatus.AGENT_DISABLED
                        else "AUTHENTICATION_FAILED"
                    )
                    return _mcp_error_result(
                        code=err_code,
                        message=exc.message,
                        correlation_id=correlation_id,
                    )

            assert auth_result.agent is not None
            execute_req = GatewayExecuteRequest(
                tool_name=params.name,
                action=validated.action,
                resource=validated.resource,
                arguments=validated.arguments,
                approval_id=validated.approval_id,
            )
            try:
                _status_code, result_model = await gateway.execute_request(
                    session,
                    agent=auth_result.agent,
                    payload=execute_req,
                    correlation_id=correlation_id,
                    settings=settings,
                )
            except ChaperoneError as exc:
                return _mcp_error_result(
                    code=exc.code,
                    message=exc.message,
                    correlation_id=correlation_id,
                )
            except Exception:
                logger.exception("Unhandled error during MCP gateway dispatch")
                return _mcp_error_result(
                    code="INTERNAL_ERROR",
                    message="An internal gateway error occurred.",
                    correlation_id=correlation_id,
                )

        body = result_model.model_dump(mode="json")
        is_error = result_model.decision == "DENY" or result_model.status == "FAILED"
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(body))],
            structured_content=body,
            is_error=is_error,
        )

    return Server(
        name="axly-chaperone",
        version=settings.app_version,
        instructions=(
            "AXLY Chaperone Security Gateway MCP Server. Every tool call is authenticated, "
            "evaluated by deterministic policies, approved if sensitive, and verified."
        ),
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
    )


async def run_stdio_server(settings: Settings | None = None) -> None:
    """Run the Chaperone MCP server over stdio transport for local AI agent clients."""
    resolved = settings or get_settings()
    configure_logging(level=resolved.log_level, json_logs=resolved.log_json)
    engine = build_engine(
        resolved.database_url,
        echo=resolved.db_echo,
        pool_size=resolved.db_pool_size,
        max_overflow=resolved.db_max_overflow,
    )
    session_factory = build_session_factory(engine)
    server = create_chaperone_mcp_server(session_factory=session_factory, settings=resolved)
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_stdio_server())

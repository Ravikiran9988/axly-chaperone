"""MCP client helper connecting to the Chaperone MCP server over SDK transports."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel.server import Server
from mcp.shared.memory import create_client_server_memory_streams


@dataclass(frozen=True, slots=True)
class McpCallOutcome:
    """Normalized MCP tool invocation outcome."""

    is_error: bool
    payload: dict[str, Any]


def _parse_call_result(result: types.CallToolResult) -> McpCallOutcome:
    if result.structured_content is not None and isinstance(result.structured_content, dict):
        return McpCallOutcome(is_error=bool(result.is_error), payload=result.structured_content)
    for item in result.content:
        if isinstance(item, types.TextContent):
            try:
                parsed = json.loads(item.text)
                if isinstance(parsed, dict):
                    return McpCallOutcome(is_error=bool(result.is_error), payload=parsed)
            except json.JSONDecodeError:
                return McpCallOutcome(
                    is_error=bool(result.is_error),
                    payload={"raw_text": item.text},
                )
    return McpCallOutcome(is_error=bool(result.is_error), payload={})


class ChaperoneMCPClient:
    """Client wrapper for interacting with the Chaperone MCP server."""

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def list_tools(self) -> list[types.Tool]:
        """List tools advertised by the Chaperone MCP server."""
        result = await self._session.list_tools()
        return list(result.tools)

    async def call_tool(
        self,
        *,
        tool_name: str,
        action: str,
        resource: str,
        arguments: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        raw_extra_args: dict[str, Any] | None = None,
    ) -> McpCallOutcome:
        """Invoke a Chaperone-mediated tool over the MCP ClientSession (no API key args)."""
        call_args: dict[str, Any] = {
            "action": action,
            "resource": resource,
            "arguments": arguments or {},
        }
        if correlation_id is not None:
            call_args["correlation_id"] = correlation_id
        if approval_id is not None:
            call_args["approval_id"] = approval_id
        if raw_extra_args:
            call_args.update(raw_extra_args)

        result = await self._session.call_tool(tool_name, arguments=call_args)
        assert isinstance(result, types.CallToolResult)
        return _parse_call_result(result)


@asynccontextmanager
async def connect_in_memory_mcp(server: Server[Any]) -> AsyncIterator[ChaperoneMCPClient]:
    """Connect a ClientSession to an in-process Chaperone MCP Server via memory streams."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams
        async with anyio.create_task_group() as tg:
            tg.start_soon(
                server.run,
                server_read,
                server_write,
                server.create_initialization_options(),
            )
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()
                try:
                    yield ChaperoneMCPClient(session)
                finally:
                    tg.cancel_scope.cancel()


@asynccontextmanager
async def connect_stdio_mcp(
    *,
    agent_api_key: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> AsyncIterator[ChaperoneMCPClient]:
    """Launch the MCP server over stdio, passing credentials strictly via subprocess env."""
    merged_env = dict(env if env is not None else os.environ)
    if agent_api_key is not None:
        merged_env["CHAPERONE_MCP_AGENT_KEY"] = agent_api_key
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "app.adapters.mcp.server"],
        env=merged_env,
        cwd=cwd,
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield ChaperoneMCPClient(session)

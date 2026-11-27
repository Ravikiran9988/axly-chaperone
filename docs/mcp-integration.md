# AXLY Chaperone — MCP Integration

AXLY Chaperone exposes a Model Context Protocol (MCP) server built on the official Python `mcp` SDK (`backend/app/adapters/mcp/`).

## Design Principle: Zero Bypass

AI clients connecting over MCP **never** talk directly to `FileToolAdapter`, `EmailToolAdapter`, or `DatabaseToolAdapter`. Every `call_tool` invocation passes through:

1. Strict Pydantic v2 schema validation (`McpFileToolInput`, `McpEmailToolInput`, `McpDatabaseToolInput` with `extra="forbid"`).
2. `authenticate_agent_key` using `agent_api_key` (or `CHAPERONE_MCP_AGENT_KEY` for local `stdio` sessions), with failed auth attempts audited before returning a sanitized MCP error.
3. `GatewayService.execute_request`, enforcing deterministic policies, human approvals (`approval_id` two-step execution supported), execution timeouts, independent verification, and append-only audit logging.
4. End-to-end `correlation_id` propagation across MCP responses and `audit_events`.

## Exposed MCP Tools

- `file_tool`: actions `read`, `write`, `list` (sandboxed to `CHAPERONE_SANDBOX_DIR`)
- `email_tool`: actions `create_draft`, `send`, `read` (local `mock_emails` store)
- `database_tool`: actions `read`, `create`, `update` (allowlisted `demo_invoices`, `demo_tasks`)

## Running Over `stdio` Transport

```powershell
# Windows PowerShell (from backend/)
$env:CHAPERONE_DATABASE_URL="postgresql+asyncpg://postgres:YOUR_PASSWORD@127.0.0.1:5432/axly_chaperone"
$env:CHAPERONE_MCP_AGENT_KEY="axly_ag_..."
.\.venv\Scripts\python.exe -m app.adapters.mcp.server
```

*(Note: MCP currently operates over `stdio` / in-memory SDK streams rather than an HTTP SSE endpoint, so the React Settings page explicitly reports MCP HTTP telemetry as not exposed.)*

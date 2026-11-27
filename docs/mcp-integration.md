# MCP Integration Guide

AXLY Chaperone exposes governance-enforced MCP tools via `ChaperoneMCPServer` (`backend/app/adapters/mcp/server.py`) and `ChaperoneMCPClient` (`backend/app/adapters/mcp/client.py`).

## Out-of-Band Authentication Design

Earlier prototypes required `agent_api_key` inside MCP tool arguments, which leaked credentials into LLM tool schemas (`tools/list`) and model contexts. Chaperone now binds agent credentials strictly **out of band**:

- **Zero Secrets in Model Schemas (`tools/list`):** `McpToolCallEnvelope` (`backend/app/adapters/mcp/schemas.py`) excludes `agent_api_key` and credential fields from every MCP tool schema exposed to an LLM.
- **Server-Side Credential Binding:** `ChaperoneMCPServer` resolves the agent identity exclusively from:
  1. `bound_agent_key` passed cleanly at server construction (in-process/transport authentication),
  2. an injected async/sync `credential_provider`, or
  3. process environment `CHAPERONE_MCP_AGENT_KEY` (via `connect_stdio_mcp(..., agent_api_key=...)` passing env to the child stdio process rather than tool arguments).
- **Fail-Closed Validation & Anti-Smuggling:**
  - Unbound MCP calls return `AUTHENTICATION_FAILED` immediately before touching any adapter and emit an audit event.
  - Any tool call attempting to smuggle credential keys (`agent_api_key`, `api_key`, `x_agent_key`, `admin_api_key`) in payload arguments fails closed with `INVALID_MCP_ARGUMENTS`.

## Available MCP Tools

- `file_tool` (`read`, `write`, `list`)
- `database_tool` (`read_records`, `update_record`)
- `email_tool` (`list_drafts`, `create_draft`, `send`)

Every MCP call routes cleanly through `GatewayService` -> `PolicyEngine` -> `ApprovalService` -> hardened adapters -> `VerificationEngine` -> hash-chained `AuditService`.

## Running the Stdio MCP Server

```powershell
cd backend
$env:CHAPERONE_MCP_AGENT_KEY="chp_agent_..."
python -m app.adapters.mcp.server
```

Do not prompt or provide agent API keys to the LLM runtime; pass them solely in the hosting transport environment.

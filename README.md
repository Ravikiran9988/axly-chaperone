# AXLY Chaperone

**Safe autonomy. Human control.**

**AXLY Chaperone** is an AI Agent Security & Governance Gateway that mediates every tool request made by AI agents through authentication, deterministic policy evaluation, human approval workflows, controlled tool adapters, independent outcome verification, and append-only audit logging.

> **Current Implementation Status (Phase 1 + Phase 2 + Phase 3):**
> - **Phase 1:** Core gateway, agent auth, tool registry, deterministic policy engine, resource validation, and append-only audit log (`POST /api/v1/gateway/evaluate`).
> - **Phase 2:** Human approval workflow, controlled tool adapters (`file_tool`, `email_tool`, `database_tool`), secure execution (`POST /api/v1/gateway/execute`), independent state verification, MCP integration (`mcp` SDK), and prompt-injection security demonstration.
> - **Phase 3:** React + Vite + Tailwind CSS governance console (`frontend/`) connected to live Chaperone APIs.

---

## Architecture Overview

```text
backend/
  app/
    main.py                     # FastAPI factory, middleware wiring, exception handlers
    cli.py                      # Bootstrap CLI (admin key generation)
    core/                       # Settings, async SQLAlchemy 2.x, JSON logging + redaction, PBKDF2 crypto, errors
    models/                     # Agent, Tool, Policy, AuditEvent, MockEmailRecord, DemoInvoice, DemoTask, ExecutionIdempotency
    schemas/                    # Strict Pydantic v2 schemas (extra="forbid")
    security/                   # Auth separation, resource normalization/validation, pure deterministic PolicyEngine
    approvals/                  # ApprovalRequest ORM, schemas, atomic ApprovalService
    adapters/
      base.py                   # BaseToolAdapter interface
      file_adapter.py           # Sandboxed FileToolAdapter (path/symlink/size checks)
      email_adapter.py          # Local Mock EmailToolAdapter (no external SMTP)
      database_adapter.py       # Parameterized DatabaseToolAdapter restricted to demo tables
      mcp/                      # Official Python MCP SDK server (stdio/memory) & client
    execution/                  # AdapterRegistry, ExecutionDispatcher (timeouts, validation)
    verification/               # VerificationRecord ORM, independent VerificationEngine
    demo/                       # Prompt-injection & human-approval end-to-end demonstration
    services/                   # Agent, Tool, Policy, Gateway, and append-only Audit services
    middleware/                 # Correlation ID, security headers, sliding-window rate limiter
    api/routes/                 # /health, /ready, /api/v1/{agents,tools,policies,approvals,audit-events,gateway}
    tests/                      # Pytest suite covering Phase 1 & Phase 2
  alembic/                      # Migrations 0001_initial_schema -> 0002_phase2_governance_execution
```

---

## Security Model & Policy Precedence

Every tool evaluation and execution request is evaluated deterministically (`app/security/policy_engine.py`) without LLM involvement:

1. **Authentication Gate:** Missing or invalid `X-Agent-Key` -> `401` and audited (`DENY`).
2. **Agent Status Gate:** Disabled agent (`status = "disabled"`) -> `403` and audited (`DENY`).
3. **Tool Gate:** Unregistered or disabled tool -> `DENY` before execution.
4. **Resource & Argument Validation Gate:** Rejects path traversal (`..`, `.`, `\`, `%2e`, `%2f`, `%5c`, null bytes, drive prefixes, leading `/`), symlink escapes, raw SQL keys, unauthorized DB tables, and mismatches between `resource` and `arguments` (including nested objects).
5. **Default Deny:** Zero matching enabled policies -> `DENY`.
6. **Explicit Deny Hard-Block:** Any matching `deny` policy overrides `allow` and `require_approval` regardless of numeric priority.
7. **Priority Precedence (`allow` vs `require_approval`):** Highest `priority` wins; on ties, `REQUIRE_APPROVAL` overrides `ALLOW` (fail-safe human control).

---

## Human Approval Workflow (Phase 2)

Sensitive actions matching `REQUIRE_APPROVAL` enter a transactional approval lifecycle (`approval_requests`):

- **Supported States:** `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `EXECUTED`, `FAILED`.
- **Payload Binding:** `ApprovalService` hashes `(agent_id, tool_name, action, resource, sanitized_arguments)` with SHA-256 (`payload_hash`). Any post-approval modification is blocked (`403 PAYLOAD_TAMPERING_DETECTED`).
- **Concurrency & Replay Protection:** Approvals use atomic conditional `UPDATE` transitions and an `execution_claimed_at` Compare-And-Swap guard so concurrent or replayed requests cannot execute an action twice.
- **Expiration & Re-evaluation:** Expired pending requests transition to `EXPIRED` (`409`). Immediately prior to execution, Chaperone re-evaluates agent status, tool enabled status, and active policies so newly added `DENY` policies block execution.
- **Admin Endpoints (`X-Admin-Key`):**
  - `GET /api/v1/approvals`
  - `GET /api/v1/approvals/{approval_id}`
  - `POST /api/v1/approvals/{approval_id}/approve` (supports `{"comment": "...", "execute_now": true|false}`)
  - `POST /api/v1/approvals/{approval_id}/reject`

---

## Controlled Mock Tools & Independent Verification

Chaperone exposes three controlled mock tools through `ExecutionDispatcher` with configured timeouts (`CHAPERONE_TOOL_EXECUTION_TIMEOUT_SECONDS`) and payload limits:

1. **`file_tool` (`filesystem`):** `read`, `write`, `list` restricted strictly to `CHAPERONE_SANDBOX_DIR` (`sandbox_data/`). Seeded sample files include `documents/invoice.txt`, `documents/project_notes.txt`, and `private/secrets.txt` (inaccessible to the demo agent). Enforces path normalization, file size limits, and symlink-segment blocking.
2. **`email_tool` (`communication`):** `create_draft`, `send`, `read` backed by `mock_emails`. Never connects to any external SMTP server.
3. **`database_tool` (`database`):** `read`, `create`, `update` using structured, column-allowlisted parameterized ORM queries restricted strictly to `demo_invoices` and `demo_tasks`. Arbitrary SQL keys are rejected.

### Independent Verification Engine
After execution, `VerificationEngine` (`app/verification/engine.py`) does **not** trust adapter return flags. It independently inspects actual system state:
- **`file_tool`:** Re-verifies sandbox file existence, size, and SHA-256 hash on disk (without storing secret file content in audit or verification records).
- **`email_tool`:** Queries `mock_emails` directly to verify recipient, subject, and `status`.
- **`database_tool`:** Queries the target demo table row by ID to verify persisted fields.
- **Statuses:** `VERIFIED`, `FAILED`, `INCONCLUSIVE`, `NOT_APPLICABLE`.

---

## Example Gateway Execution Requests & Responses

`POST /api/v1/gateway/execute` (Header: `X-Agent-Key: <agent_key>`, optional `Idempotency-Key`):

**Approval Required (`202 Accepted`):**
```json
{
  "correlation_id": "demo-finance-email-004",
  "decision": "REQUIRE_APPROVAL",
  "status": "PENDING",
  "message": "Administrator approval required",
  "tool_name": "email_tool",
  "action": "send",
  "resource": "finance@company.com",
  "agent_id": "...",
  "approval_id": "..."
}
```

**Denied (`403 Forbidden`):**
```json
{
  "correlation_id": "demo-inject-private-002",
  "decision": "DENY",
  "status": "BLOCKED",
  "message": "Denied by explicit policy 'demo-deny-private-files' (priority 500)",
  "tool_name": "file_tool",
  "action": "read",
  "resource": "private/secrets.txt",
  "agent_id": "..."
}
```

**Executed & Verified (`200 OK`):**
```json
{
  "correlation_id": "demo-read-invoice-001",
  "decision": "ALLOW",
  "status": "EXECUTED",
  "message": "Read 'documents/invoice.txt' (164 bytes).",
  "tool_name": "file_tool",
  "action": "read",
  "resource": "documents/invoice.txt",
  "agent_id": "...",
  "output": { "path": "documents/invoice.txt", "content": "...", "size_bytes": 164 },
  "verification": {
    "verification_id": "...",
    "status": "VERIFIED",
    "method": "sandbox_file_presence_check",
    "message": "Read target independently confirmed inside sandbox."
  }
}
```

---

## MCP Integration

Chaperone provides an MCP-compatible server built on the official Python `mcp` SDK (`app/adapters/mcp/server.py`, `client.py`, `schemas.py`):
- Registers `file_tool`, `email_tool`, and `database_tool` with strict Pydantic v2 input schemas.
- Routes every `call_tool` invocation through `authenticate_agent_key` and `GatewayService.execute_request` — there is **no** direct adapter bypass.
- Propagates `correlation_id` end-to-end and returns sanitized structured MCP errors without leaking secrets.

### Running the MCP Server (`stdio` transport)

```powershell
# Windows PowerShell (from backend/)
$env:CHAPERONE_DATABASE_URL="postgresql+asyncpg://postgres:YOUR_PASSWORD@localhost:5432/axly_chaperone"
$env:CHAPERONE_MCP_AGENT_KEY="axly_ag_..."
.\.venv\Scripts\python.exe -m app.adapters.mcp.server
```

```bash
# Linux / macOS (from backend/)
export CHAPERONE_DATABASE_URL="postgresql+asyncpg://postgres:YOUR_PASSWORD@localhost:5432/axly_chaperone"
export CHAPERONE_MCP_AGENT_KEY="axly_ag_..."
python -m app.adapters.mcp.server
```

---

## Prompt-Injection Security Demo

Run the self-contained Phase 2 demonstration (exercises MCP client -> MCP server -> Gateway -> Policy Engine -> Approval Workflow -> Adapters -> Verification -> Chronological Audit):

```powershell
# Windows PowerShell (from backend/)
.\.venv\Scripts\python.exe -m app.demo.prompt_injection_demo
```

```bash
# Linux / macOS (from backend/)
python -m app.demo.prompt_injection_demo
```

The demo reads `documents/invoice.txt`, extracts `INV-2026-001` (`45000 INR`), blocks injected attempts to read `private/secrets.txt` and exfiltrate to `attacker@example.com`, routes the safe summary email to `finance@company.com` through human approval, independently verifies delivery in `mock_emails`, and confirms zero leaked secrets in the chronological audit log.

---

## Local Development, Migrations, and Testing

### Setup (Windows PowerShell)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m app.cli generate-admin-key
Copy-Item .env.example .env
# Edit .env with PostgreSQL CHAPERONE_DATABASE_URL and CHAPERONE_ADMIN_API_KEY
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Setup (Linux / macOS)
```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.cli generate-admin-key
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Running Tests & Lint Checks
```powershell
# Windows PowerShell (from backend/)
.\.venv\Scripts\pytest.exe -v
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
```

*(Tests default to an isolated temporary `sqlite+aiosqlite` database and temp sandbox directory; set `CHAPERONE_TEST_DATABASE_URL` to run against an isolated PostgreSQL test database.)*

---

## Frontend Console (Phase 3)

The **AXLY Chaperone** administrative web console lives in `frontend/` and is built with React 18, JavaScript, Vite, Tailwind CSS, React Router, TanStack Query, Axios, Recharts, React Hook Form, Zod, and Lucide React.

### Frontend Architecture

```text
frontend/
  .env.example                  # Frontend environment configuration template
  vite.config.js                # Vite dev server, proxy (/api, /health, /ready), and Vitest config
  src/
    app/                        # App shell root, providers (Theme, Query, Toast, Auth), and router
    components/
      layout/                   # AppShell, Sidebar, Topbar, ProtectedRoute, BrandLogo
      ui/                       # Button, Card, Badge, StatusBadge, Modal, Drawer, ConfirmDialog, etc.
      charts/                   # Recharts widgets backed strictly by live API responses
      tables/                   # DataTable with loading, error, and empty states
      forms/                    # AgentFormModal, ApiKeyRevealModal, ToolFormModal, PolicyFormModal
      feedback/                 # ErrorBoundary, ToastContainer
    pages/                      # Login, Overview, Agents, AgentDetails, Tools, Policies, Approvals, SecurityEvents, AuditLogs, Settings
    services/                   # Centralized Axios client (api.js) + domain endpoint modules
    hooks/                      # TanStack Query hooks and dashboard aggregation hook
    context/                    # AuthContext (in-memory key session), ThemeContext, ToastContext
    utils/                      # Formatters, defensive secret redaction, Zod schemas, tool adapter capability metadata
    tests/                      # Vitest + React Testing Library test suites
```

### Installation & Environment Variables

```powershell
# From repository root
cd frontend
npm install
Copy-Item .env.example .env
```

```bash
# Linux / macOS
cd frontend
npm install
cp .env.example .env
```

Key variables in `frontend/.env.example`:
- `VITE_API_BASE_URL` — Backend API base URL (e.g. `http://127.0.0.1:8000`, or leave blank `""` in local dev to route through Vite's proxy).
- `VITE_API_TIMEOUT_MS` — Request timeout in milliseconds (default: `15000`).
- `VITE_AUTH_MODE` — `admin_key` (current backend `X-Admin-Key` header verification) or `session_cookie` (Phase 4 HTTP-only cookie integration contract).
- `VITE_PROXY_TARGET` — Backend URL used by Vite's dev proxy when `VITE_API_BASE_URL` is blank (`http://127.0.0.1:8000`).

> **Security:** Never place `CHAPERONE_ADMIN_API_KEY`, agent API keys (`axly_ag_*`), or secrets in `frontend/.env` or `VITE_*` variables.

### Backend Connection & CORS Configuration

When running the frontend directly against `http://127.0.0.1:8000` (non-proxied cross-origin mode with `VITE_API_BASE_URL=http://127.0.0.1:8000`), configure `backend/.env`:

```env
CHAPERONE_CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]
CHAPERONE_CORS_ALLOW_METHODS=["GET","POST","PATCH"]
CHAPERONE_CORS_ALLOW_HEADERS=["Content-Type","X-Admin-Key","X-Agent-Key","X-Correlation-ID","X-Admin-Actor"]
```

*(Note: `X-Admin-Actor` is optional in the UI login form and only sent if specified; including it in `CHAPERONE_CORS_ALLOW_HEADERS` enables custom reviewer actor attribution cross-origin.)*

### Authentication Integration

Because the Phase 1/2 backend uses a single administrative secret (`X-Admin-Key` verified against `CHAPERONE_ADMIN_API_KEY`) without a session/cookie login endpoint:
- The Login page validates the entered Admin API Key (and optional `X-Admin-Actor`) live against `GET /api/v1/agents?page=1&page_size=1`.
- The credential is held **strictly in JavaScript memory** (never written to `localStorage` or `sessionStorage`) and automatically cleared on logout, `401`/`ADMIN_NOT_CONFIGURED` API responses, tab reload, or 30 minutes of inactivity.
- Agent API keys issued via `POST /api/v1/agents` are displayed **once** in `ApiKeyRevealModal` and wiped from memory upon dismissal.

### Development, Test & Build Commands

Run backend and frontend together in two terminals:

```powershell
# Terminal 1 — Backend (from backend/)
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 — Frontend (from frontend/)
npm run dev
```

Frontend verification commands (from `frontend/`):

```powershell
npm test         # Run Vitest + React Testing Library suite
npm run build    # Create production bundle in frontend/dist/
npm run preview  # Preview production build locally
```

### Documented Backend Endpoint Gaps

The frontend integrates strictly with existing backend endpoints without fabricating data or inventing APIs. The following backend gaps are documented for Phase 4:

1. **Admin Session Authentication (`/api/v1/auth/login`, `/logout`, `/me`):** No dedicated login or HTTP-only cookie session endpoint exists yet (`VITE_AUTH_MODE=session_cookie` is prepared as the frontend contract).
2. **Overview Metrics / Aggregation Endpoint (`/api/v1/metrics` or `/stats`):** Overview KPIs and charts derive from `PaginatedResponse.total` counts and fetched audit/approval pages (`page_size=100`). When total events exceed 100, charts explicitly indicate the sampled window.
3. **Runtime Tool Capabilities Endpoint:** `ToolResponse` does not expose `supported_actions` or whether an execution adapter exists in `AdapterRegistry`. The Tools UI clearly distinguishes the built-in Phase 2 adapters (`file_tool`, `email_tool`, `database_tool`) from policy-evaluation-only tools.
4. **Policy & Agent Deletion / Key Rotation:** `DELETE /api/v1/policies/{id}`, `DELETE /api/v1/agents/{id}`, and `POST /api/v1/agents/{id}/rotate-key` do not exist; the UI exposes only backend-supported enable/disable `PATCH` toggles.
5. **Audit Date-Range & Text-Search Query Params:** `GET /api/v1/audit-events` supports exact `correlation_id`, `agent_id`, `tool_name`, `decision`, `event_type`, `verification_status`, `approval_id`, and `order`, but not `start_time`/`end_time` or full-text `q`. Time-range and keyword filters operate client-side on the loaded page and state that scope explicitly.
6. **MCP & Non-Secret Runtime Telemetry:** No HTTP endpoint exposes MCP `stdio` server health or non-secret gateway settings.

---

## Known Security Limitations

1. **Single Bootstrap Admin Key:** Phase 2 still uses `CHAPERONE_ADMIN_API_KEY` rather than multi-admin RBAC/OIDC user identities.
2. **In-Process Rate Limiter:** `RateLimitMiddleware` uses process-local memory; multi-worker deployments require Redis.
3. **Mock Providers Only:** `email_tool` and `database_tool` operate exclusively against local database tables; no production SMTP or arbitrary external DB connectors are enabled.
4. **Symlink Privileges on Windows:** OS-level symlink creation without Developer Mode may require elevation; `FileToolAdapter` defends against symlinks whenever present via per-segment `islink`/`resolve` checks.
5. **App-Layer Audit Immutability:** Production PostgreSQL roles should additionally revoke `UPDATE` and `DELETE` privileges on `audit_events` and `verification_records`.

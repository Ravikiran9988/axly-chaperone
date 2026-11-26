# AXLY Chaperone

**Safe autonomy. Human control.**

**AXLY Chaperone** is an AI Agent Security & Governance Gateway that mediates every tool access request made by AI agents through authentication, deterministic policy evaluation, safe resource normalization, and append-only audit logging.

> **Phase 1 Scope (Foundation & Security Core):**
> Phase 1 implements the security control plane, deterministic policy decision point (`POST /api/v1/gateway/evaluate`), tool registry, agent identity lifecycle, and immutable audit trail. **No tools are executed in Phase 1**, and **no frontend is included yet** (scheduled for Phase 3).

---

## Architecture Overview

```text
backend/
  app/
    main.py                     # FastAPI factory, middleware wiring, exception handlers
    cli.py                      # Bootstrap CLI (admin key generation)
    core/
      config.py                 # Typed environment configuration with fail-closed prod checks
      database.py               # Async SQLAlchemy 2.x engine, session factory, connectivity probe
      logging.py                # Structured JSON logging + automatic secret redaction filter
      security.py               # API key generation, PBKDF2-HMAC-SHA256 hashing, constant-time verify
      exceptions.py             # Sanitized centralized error envelopes & HTTP handlers
    models/
      enums.py                  # AgentStatus, RiskLevel, PolicyDecision, ExecutionStatus, VerificationStatus
      types.py                  # UTC-enforced DateTime column type
      agent.py                  # Agent identities (key_id, salted hash, status)
      tool.py                   # Registered tool definitions (category, risk_level, enabled)
      policy.py                 # Versioned deterministic policies
      audit.py                  # Append-only AuditEvent records (JSONB metadata on PostgreSQL)
    schemas/                    # Strict Pydantic v2 request/response schemas (extra="forbid")
    security/
      authentication.py         # Separate X-Admin-Key and X-Agent-Key verification
      authorization.py          # Control-plane vs gateway access separation
      resource_validator.py     # Tool-category normalization, traversal blocking, arg cross-checks
      policy_engine.py          # Pure deterministic Python policy evaluator
    services/                   # Business logic for agents, tools, policies, gateway, audit
    middleware/                 # Correlation ID, security headers, Phase 1 sliding-window rate limit
    api/routes/                 # /health, /ready, /api/v1/{agents,tools,policies,audit-events,gateway}
    tests/                      # Pytest unit, integration, security, and Alembic migration tests
  alembic/                      # Async Alembic migrations (0001_initial_schema)
  alembic.ini
  pyproject.toml
  requirements.txt
  requirements-dev.txt
  .env.example
```

---

## Policy Engine Precedence Rules

Every gateway request is evaluated deterministically in pure Python (`app/security/policy_engine.py`) without any LLM involvement:

1. **Authentication Gate:** Missing or invalid `X-Agent-Key` -> rejected (`401`) and audited (`DENY`).
2. **Agent Status Gate:** Disabled agents (`status = "disabled"`) -> rejected (`403`) and audited (`DENY`).
3. **Tool Gate:** Unregistered or disabled tools (`enabled = false`) -> always `DENY`.
4. **Resource & Argument Validation Gate:** Path traversal (`..`, `\`, `%2e%2e`, null bytes, absolute/drive paths), malformed URLs/emails/DB identifiers, or mismatches between `resource` and `arguments` (including nested objects) -> always `DENY`.
5. **Default Deny:** Zero matching enabled policies -> `DENY` (`"No matching permission policy"`).
6. **Explicit Deny Hard-Block:** If **any** matching enabled policy specifies `deny`, the final decision is **`DENY`** regardless of priority (explicit denials cannot be bypassed by `require_approval` or `allow`). Ties among multiple `deny` policies pick the highest `priority`, then highest specificity, then UUID order.
7. **Priority Precedence (`allow` vs `require_approval`):** Among non-deny matches, the highest numeric `priority` (`0..10000`) wins. On an equal-priority tie, **`REQUIRE_APPROVAL` overrides `ALLOW`** (fail-safe human control).

### Supported `resource_scope` Patterns
- `*` — any validated, normalized resource
- `<prefix>/*` — segment-boundary recursive prefix (e.g., `documents/*` matches `documents/invoice.txt` but **not** `documents_private/invoice.txt`)
- `*@<domain>` — exact email domain match (e.g., `*@company.com`)
- `<scheme>://<host>/*` — exact origin + path prefix (e.g., `https://api.example.com/*`)
- `<exact>` — exact normalized identifier match

---

## Administrative Bootstrap & Authentication

Administrative routes (`/api/v1/agents`, `/api/v1/tools`, `/api/v1/policies`, `/api/v1/audit-events`) are strictly separated from agent gateway routes (`/api/v1/gateway/evaluate`):

- **No hardcoded credentials:** `CHAPERONE_ADMIN_API_KEY` has no default value. Admin routes fail closed (`503 ADMIN_NOT_CONFIGURED`) if unset, and `staging`/`production` environments refuse startup unless `CHAPERONE_ADMIN_API_KEY` is at least 32 characters.
- **Agent credentials:** `POST /api/v1/agents` generates a high-entropy key (`axly_ag_<key_id>_<secret>`), returns the plaintext key **once**, and persists only a salted `PBKDF2-HMAC-SHA256` hash (`200,000` iterations by default, optionally mixed with `CHAPERONE_API_KEY_PEPPER`). Agent keys never grant access to admin endpoints, and admin keys cannot evaluate tools on `/api/v1/gateway/evaluate`.

---

## Local Development Setup (No Docker Required)

Prerequisites:
- **Python 3.12+**
- **PostgreSQL** installed and running locally (for example PostgreSQL 18 on `localhost:5432`)

### 1. Create Virtual Environment & Install Dependencies

#### Windows PowerShell
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

*(If using `uv`: `uv venv --python 3.12 .venv` then `uv pip install --python .venv\Scripts\python.exe -r requirements-dev.txt`.)*

#### Linux / macOS
```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### 2. Configure Environment & Generate Admin Bootstrap Key

Generate a cryptographically random admin key:

```powershell
# Windows PowerShell (from backend/)
.\.venv\Scripts\python.exe -m app.cli generate-admin-key
```

```bash
# Linux / macOS (from backend/)
python -m app.cli generate-admin-key
```

Copy `.env.example` to `.env` and populate `CHAPERONE_DATABASE_URL` and `CHAPERONE_ADMIN_API_KEY`:

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

```bash
# Linux / macOS
cp .env.example .env
```

### 3. Initialize PostgreSQL Database & Run Migrations

Create the database in your local PostgreSQL instance (e.g. via `psql` or pgAdmin):

```sql
CREATE DATABASE axly_chaperone;
```

Run Alembic migrations from `backend/`:

```powershell
# Windows PowerShell
.\.venv\Scripts\alembic.exe upgrade head
```

```bash
# Linux / macOS
alembic upgrade head
```

To inspect the PostgreSQL DDL without connecting to a live server:

```bash
alembic upgrade head --sql
```

### 4. Start the Backend Server

```powershell
# Windows PowerShell (from backend/)
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
# Linux / macOS (from backend/)
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

OpenAPI interactive docs: `http://127.0.0.1:8000/docs`

### 5. Run Tests & Linting

By default, `pytest` runs against an isolated temporary SQLite async database (`sqlite+aiosqlite`) so it never touches a developer's local PostgreSQL database. To run the test suite against an isolated PostgreSQL test database, set `CHAPERONE_TEST_DATABASE_URL`.

```powershell
# Windows PowerShell (from backend/)
.\.venv\Scripts\pytest.exe -v
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
```

```bash
# Linux / macOS (from backend/)
pytest -v
ruff check .
ruff format --check .
```

---

## API Summary

| Method & Path | Auth | Purpose |
|---|---|---|
| `GET /health` | None | Liveness probe |
| `GET /ready` | None | Readiness probe with DB `SELECT 1` check |
| `POST /api/v1/agents` | `X-Admin-Key` | Register agent & emit one-time API key |
| `GET /api/v1/agents` | `X-Admin-Key` | List agents (paginated, no secrets) |
| `GET /api/v1/agents/{agent_id}` | `X-Admin-Key` | Get agent details (no secrets) |
| `PATCH /api/v1/agents/{agent_id}/status` | `X-Admin-Key` | Activate or disable agent |
| `POST /api/v1/tools` | `X-Admin-Key` | Register tool definition |
| `GET /api/v1/tools` | `X-Admin-Key` | List tools (paginated & filterable) |
| `GET /api/v1/tools/{tool_name}` | `X-Admin-Key` | Get tool definition |
| `PATCH /api/v1/tools/{tool_name}` | `X-Admin-Key` | Enable/disable or update tool |
| `POST /api/v1/policies` | `X-Admin-Key` | Create authorization policy |
| `GET /api/v1/policies` | `X-Admin-Key` | List policies ordered by priority |
| `GET /api/v1/policies/{policy_id}` | `X-Admin-Key` | Get policy details |
| `PATCH /api/v1/policies/{policy_id}` | `X-Admin-Key` | Update policy (increments `version`) |
| `GET /api/v1/audit-events` | `X-Admin-Key` | Query append-only audit trail |
| `GET /api/v1/audit-events/{event_id}` | `X-Admin-Key` | Inspect single audit event |
| `POST /api/v1/gateway/evaluate` | `X-Agent-Key` | Evaluate & audit tool access (no execution) |

---

## Known Phase 1 Limitations

1. **Single-Key Admin Auth:** Phase 1 uses a single environment-configured `CHAPERONE_ADMIN_API_KEY` rather than multi-user RBAC, OIDC/JWT, or short-lived admin sessions.
2. **In-Memory Rate Limiter:** The sliding-window rate limiter (`RateLimitMiddleware`) operates per worker process in memory; multi-worker deployments require a shared Redis store.
3. **No Tool Execution or Approval Workflow Execution:** `REQUIRE_APPROVAL` decisions are returned and audited, but human approval queues and sandboxed tool adapters belong to Phase 2.
4. **Static Resource Validation:** Argument validation inspects canonical path/URL/email/database shapes and nested resource keys; full per-tool JSON Schema validation and runtime sandboxing will be introduced with tool execution adapters in Phase 2.
5. **No Database-Level `REVOKE UPDATE/DELETE` Trigger Yet:** Audit immutability is enforced at the application API/service layer (`AuditService`); PostgreSQL role separation (`REVOKE UPDATE, DELETE ON audit_events`) is recommended before production deployment.

# AXLY Chaperone

> **Safe autonomy. Human control.**  
> **AI Agent Security & Governance Gateway**

AXLY Chaperone enforces deterministic capability governance between autonomous AI agents (and LLM tool callers) and real backend capabilities. Every tool invocation passes through Chaperone's gateway or MCP boundary for credential verification, default-deny policy evaluation, human-in-the-loop approval, TOCTOU-hardened controlled execution, independent outcome verification, and chained tamper-evident audit logging.

---

## Core Guarantees & Architecture

```
Agent / Optional LLM Client (zero agent keys in model arguments)
   │
   ▼  MCP (out-of-band key binding / env) or REST (X-Agent-Key header)
FastAPI Gateway
   ├── Agent Auth (PBKDF2-HMAC-SHA256 @ 200k iterations, constant-time compare, active-status check)
   ├── Rate Limiter (sliding window; single-worker in-memory, WAF/Redis recommended for multi-worker)
   ├── Deterministic PolicyEngine (default-deny; EXPLICIT_DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY)
   ├── Approval Workflow (canonical SHA-256 payload hash, TTL expiry, atomic single-execution lock)
   ├── Controlled Tool Adapters (POSIX dir_fd/O_NOFOLLOW & Win32 reparse-point handle checks + atomic write)
   ├── VerificationEngine (write verification, read SHA-256/byte-size match, directory entry verification)
   └── AuditService (sequential hash-chained SHA-256 audit log across metadata & decision fields)
   │
   ▲  HttpOnly Cookie Session + X-CSRF-Token + RBAC (super_admin | approver | viewer)
React Governance Console (Vite + Tailwind + TanStack Query + Recharts)
```

### Security Highlights

- **Out-of-Band MCP Authentication:** `agent_api_key` is completely absent from MCP `tools/list` schemas and tool-call arguments. ChaperoneMCPServer binds credentials via server constructor/environment (`CHAPERONE_MCP_AGENT_KEY`) and fails closed when unbound or when credential keys are smuggled in arguments.
- **Individual Admin Accounts, Sessions & RBAC:** Client-supplied `X-Admin-Actor` headers are ignored/rejected as identity proof. Administrators authenticate via `POST /api/v1/auth/login` (`AdminUser` PBKDF2 accounts or opt-in bootstrap key) receiving short-lived `HttpOnly`, `SameSite`, `Secure`-capable `chaperone_session` cookies and bound `X-CSRF-Token` validation, with server-side session revocation (`POST /api/v1/auth/logout`) and role enforcement (`super_admin`, `approver`, `viewer`).
- **Chained Tamper-Evident Audit Log:** `audit_events` tracks monotonic `chain_seq` and `previous_hash` coordinated via `audit_chain_state` (`pg_advisory_xact_lock` on PostgreSQL; per-engine serialization on SQLite). Canonical SHA-256 hashing covers action fields plus `policy_metadata` and `execution_metadata`, and `GET /api/v1/audit-events/integrity` detects middle/tail/head deletions, field edits, or timestamp reordering.
- **TOCTOU-Hardened Filesystem Execution:** POSIX adapters traverse and open directories via `dir_fd` + `O_NOFOLLOW` and write atomically via temp file + `os.fsync` + `os.replace`. Windows adapters open handles with `FILE_FLAG_OPEN_REPARSE_POINT`, verify `FILE_ATTRIBUTE_REPARSE_POINT` is unset and `GetFinalPathNameByHandleW` resolves strictly inside the sandbox root, and perform read/write operations on verified OS handles.
- **Outcome Verification:** `VerificationEngine` receives sanitized `execution_output` and independently re-verifies `file_tool.write`, `file_tool.read` (byte length and SHA-256 digest without logging plaintext contents), `file_tool.list` (sorted entry names, types, sizes, and manifest digest), plus database/email state transitions.

### Honest Scope & Known Limitations

- **Audit Chain Trust Boundary:** Hash chaining detects accidental corruption and naive row/metadata edits inside SQL, **not** a compromised database administrator or OS root who rewrites both `audit_events` and `audit_chain_state`. Production deployments should ship event hashes to an external WORM store or append-only SIEM (`docs/security-model.md`).
- **Prompt Injection Defense:** Chaperone enforces **capability-level authorization**, so injected prompts cannot invoke blocked tools or out-of-scope resources. Subtle semantic misuse of *already authorized* capabilities requires human approval rules (`REQUIRE_APPROVAL`).
- **In-Memory Rate Limiter:** Default sliding-window rate limiting runs per FastAPI worker process; multi-worker deployments must enforce limits at Nginx/WAF or swap in a shared Redis store.
- **Database Verification in Local Windows vs CI:** Because local Windows PostgreSQL credentials were not provisioned in `.env`, local test/benchmark runs executed against isolated `sqlite+aiosqlite` temp databases, whereas `.github/workflows/ci.yml` executes Alembic migrations, pytest, and the 68-scenario benchmark against live **PostgreSQL 16**.

---

## Project Structure

```text
.
├── backend/
│   ├── alembic/                 # Schema migrations (0001..0004_security_remediation)
│   ├── app/
│   │   ├── adapters/            # File (POSIX/Win32 hardened), Database, Email & MCP adapter/server/client
│   │   ├── api/routes/          # Auth (cookies/CSRF/RBAC), Agents, Tools, Policies, Approvals, Gateway, Audit
│   │   ├── approvals/           # Approval state machine, TTL expiry, atomic single-execution claim
│   │   ├── benchmark/           # Reproducible 68-scenario security & latency benchmark runner
│   │   ├── core/                # Config, database sessions, logging redaction, rate limiter, crypto helpers
│   │   ├── demo/                # Adversarial prompt-injection & hackathon demos (auto | llm | fallback)
│   │   ├── execution/           # Dispatcher with timeouts, correlation IDs, verification handoff
│   │   ├── models/              # SQLAlchemy ORM models (AdminUser, AdminSession, AuditChainState, ...)
│   │   ├── policy/              # Deterministic default-deny policy engine
│   │   ├── security/            # Cookie/CSRF/RBAC & key authentication dependencies
│   │   ├── services/            # Agent, Tool, Policy, Gateway, Audit services
│   │   ├── tests/               # Backend unit, integration, concurrency, MCP, LLM & Phase 1-4 test suites
│   │   └── verification/        # Independent post-execution VerificationEngine
├── frontend/                    # React + Vite + Tailwind + TanStack Query + Recharts governance console
├── deploy/                      # Dockerfiles, docker-compose.yml, nginx.conf, startup scripts
├── benchmarks/results/          # Timestamped & latest_benchmark.{json,md} reports
├── docs/                        # Architecture, Security Model, Policy Engine, MCP, Benchmark, Demo, Deploy
└── .github/workflows/ci.yml     # Lint, PostgreSQL 16 CI migrations/tests/benchmark, frontend audit/build, Gitleaks
```

---

## Quick Start (Local Development)

### 1. Backend Setup (Python 3.12+)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env
# Edit backend/.env with PostgreSQL connection string & strong secrets (>= 32 chars)
```

Run migrations (`0004_security_remediation`) and create your first named administrator account:

```powershell
alembic upgrade head
python -m app.cli generate-admin-key
python -m app.cli create-admin-user --username secadmin --role super_admin
```

Start the API server (single worker when relying on the built-in rate limiter):

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Frontend Setup (Node.js 22+)

```powershell
cd frontend
npm ci
copy .env.example .env   # Keep VITE_API_BASE_URL empty to use same-origin Vite proxy for cookies
npm run dev
```

Open `http://localhost:5173`, sign in with your `super_admin` username and password (or the opt-in bootstrap key toggle during initial dev setup), and inspect Overview, Agents, Tools, Policies, Approvals, Security Events, Audit Logs (including hash-chain integrity check), and Settings.

### 3. Running Demos & Benchmark

```powershell
cd backend
# Adversarial prompt-injection & hackathon demo (auto uses OpenAI-compatible env if set, else fallback)
python -m app.demo.hackathon_demo --mode fallback
# Strict real-LLM mode (requires CHAPERONE_LLM_API_KEY or OPENAI_API_KEY env var)
# $env:CHAPERONE_LLM_API_KEY="sk-..."; python -m app.demo.hackathon_demo --mode llm

# Reproducible 68-scenario security benchmark (supports CHAPERONE_BENCHMARK_DATABASE_URL for PostgreSQL)
python -m app.benchmark.runner
```

---

## Latest Benchmark Snapshot

Measured `2026-11-27T17:01:06Z` at commit `8750f0e` (`pbkdf2_iterations=200000`, `rate_limit_enabled=True (120/60s)`, `sqlite+aiosqlite` isolated local run; full report in [latest_benchmark.md](benchmarks/results/latest_benchmark.md)):

| Metric | Measured Result |
|---|---|
| Total Scenarios | **68** (34 malicious / 34 legitimate) |
| Security Blocking Rate | **100.00%** (34 / 34) |
| Legitimate Task Success Rate | **100.00%** (34 / 34) |
| False Positives / False Negatives | **0 / 0** |
| Policy & Outcome Verification Accuracy | **100.00%** (51 / 51 policy, 28 / 28 verification) |
| Pure `PolicyEngine.evaluate()` Latency | `p50 = 0.054 ms`, `p95 = 0.145 ms`, `max = 0.277 ms` |
| Controlled Tool Execution Latency | `p50 = 4.805 ms`, `p95 = 18.366 ms`, `max = 19.609 ms` |
| Full Gateway Request Latency (incl. 200k PBKDF2 + SQLite IO) | `p50 = 199.001 ms`, `p95 = 327.134 ms`, `max = 963.133 ms` |

---

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Security Model & Threat Boundaries](docs/security-model.md)
- [Deterministic Policy Engine](docs/policy-engine.md)
- [MCP Integration Guide](docs/mcp-integration.md)
- [Benchmark Methodology](docs/benchmark-methodology.md)
- [Live Hackathon Demo Guide](docs/demo-guide.md)
- [Deployment & Hardening Guide](docs/deployment.md)
- [Hackathon Submission Summary](docs/hackathon-submission.md)

## Licensing Status

No `LICENSE` file is currently committed to this repository. Establish an explicit software license (e.g., Apache-2.0 or MIT) with repository maintainers prior to external distribution.

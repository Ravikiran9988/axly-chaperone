# Architecture Overview

AXLY Chaperone acts as an inline security and governance proxy between AI agents (or MCP servers) and controlled execution adapters.

## Request & Enforcement Flow

1. **Ingress (`REST Gateway` or `ChaperoneMCPServer`):**
   - **REST API:** Agent sends `POST /api/v1/tools/execute` or `/evaluate` with `X-Agent-Key` and correlation ID.
   - **MCP (`mcp` Python SDK):** LLM discovers sanitized tool schemas (`tools/list`) with **zero** credential fields. `ChaperoneMCPServer` binds the agent API key out-of-band (constructor `bound_agent_key` / `credential_provider` / `CHAPERONE_MCP_AGENT_KEY`), rejects smuggled credential keys (`agent_api_key`, `api_key`, `x_agent_key`, `admin_api_key`), and forwards into the gateway pipeline.
2. **Authentication & Session Security:**
   - **Agent requests:** `AgentAuth` verifies `X-Agent-Key` via PBKDF2-HMAC-SHA256 (`200,000` default iterations + optional pepper) + constant-time digest compare + active `AgentStatus.ACTIVE` enforcement.
   - **Administrator requests:** Browser console and CLI/API users authenticate via `POST /api/v1/auth/login` (`AdminUser` username/password or opt-in bootstrap key) receiving a server-persisted `AdminSession` cookie (`chaperone_session`, `HttpOnly`, `SameSite=lax|strict`, `Secure` configurable/enforced in production) and paired CSRF token (`chaperone_csrf` + `X-CSRF-Token` double-submit validation on unsafe methods). Client-supplied `X-Admin-Actor` headers are never trusted.
   - **RBAC:** `super_admin` controls agent/tool/policy lifecycle and user administration; `approver` and `super_admin` review approvals; `viewer` holds read-only inspection access.
3. **Deterministic Policy Evaluation (`PolicyEngine`):**
   - Disabled agents or disabled/unregistered tools fail closed before policy rule matching.
   - Active rules matching `(agent, tool, action)` evaluate against resource patterns in canonical order: `EXPLICIT_DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY`.
   - Policy decisions never delegate to an LLM.
4. **Human Approval Workflow (`ApprovalService`):**
   - `REQUIRE_APPROVAL` persists sanitized normalized request parameters and a canonical `payload_hash` (SHA-256) with configurable TTL (`CHAPERONE_APPROVAL_TTL_SECONDS`, default `900s`).
   - Reviewer identity is derived strictly from the server-verified `AdminPrincipal`.
   - Execution verifies TTL expiry, re-evaluates payload hash against tampering, and atomically claims `status = 'approved' -> 'executing'` in SQL so concurrent replay races yield at most one execution (`409 Conflict` for duplicates).
5. **Controlled Execution Adapters (`ExecutionDispatcher`):**
   - `file_tool` enforces sandbox confinement via POSIX `dir_fd` + `O_NOFOLLOW` / atomic temp-file swap and Windows `FILE_FLAG_OPEN_REPARSE_POINT` handle attribute + `GetFinalPathNameByHandleW` verification.
   - `database_tool` restricts actions to an allowlisted parameterized SQLAlchemy repository slice (`read_records`, `update_record`).
   - `email_tool` enforces schema validation, draft creation, and gateway approval on external sends.
6. **Post-Execution Outcome Verification (`VerificationEngine`):**
   - Independently inspects controlled system state alongside sanitized `execution_output`:
     - `file_tool.write`: verifies file presence, non-reparse handle safety, byte length, and SHA-256 checksum.
     - `file_tool.read`: verifies reported byte size and SHA-256 hash against the actual sandbox file without storing plaintext file content in audit tables.
     - `file_tool.list`: verifies sorted entry names, types, byte sizes, and manifest digest against live sandbox directory listing.
     - `database_tool` & `email_tool`: confirms persisted database record updates and outbox/draft records.
7. **Hash-Chained Audit Log (`AuditService`):**
   - Sequential `chain_seq` allocated under `AuditChainState` concurrency locking (`pg_advisory_xact_lock` on PostgreSQL; per-engine async lock on SQLite).
   - Canonical recursive SHA-256 hash spans `chain_seq`, `previous_hash`, `timestamp`, `actor_type`, `actor_id`, `correlation_id`, `action`, `tool_name`, `decision`, `execution_status`, `policy_metadata`, and `execution_metadata`.
   - Full-chain verification (`GET /api/v1/audit-events/integrity`) checks contiguous `chain_seq`, hash continuity, metadata consistency, unchained row detection, and non-decreasing timestamps.

## Database & Migration Architecture

Alembic revisions (`backend/alembic/versions/`):
- `0001_initial_schema.py`: `agents`, `tools`, `policies`, `approvals`, `audit_events`, `verification_results`
- `0002_phase2_approval_constraints.py`: single-execution / payload constraints
- `0003_security_hardening_indexes.py`: operational query indexes
- `0004_security_remediation.py`: `admin_users`, `admin_sessions`, `audit_chain_state`, plus `chain_seq` and `previous_hash` columns/indexes on `audit_events`

## Frontend Architecture

- React 18 + JavaScript + Vite + Tailwind CSS + TanStack Query + React Router + Recharts + Zod.
- `AuthContext` probes `GET /api/v1/auth/session` with `withCredentials: true` on startup and attaches `X-CSRF-Token` (kept strictly in JS memory / CSRF cookie) to state-changing requests.
- Zero credentials, session tokens, or API keys are persisted in browser `localStorage` or `sessionStorage`.

# AXLY Chaperone — Hackathon Submission Material

## Short Description
**AXLY Chaperone** (*Safe autonomy. Human control.*) is an AI Agent Security & Governance Gateway that intercepts every tool call made over HTTP or MCP, authenticates the agent, evaluates deterministic least-privilege policies, gates sensitive actions behind SHA-256-bound human approvals, executes only through controlled adapters, independently verifies outcomes, and preserves an append-only tamper-evident audit trail.

## Problem Statement
Autonomous AI agents connected to filesystems, email, and databases routinely operate with overly broad credentials and zero runtime mediation. A single indirect prompt injection hidden inside an untrusted document—or a hallucinated parameter from a model—can trick an agent into reading private secrets, exfiltrating data to external recipients, or modifying production database rows. Worse, standard agent frameworks blindly trust tool return booleans without checking whether an intended state change actually happened safely.

## Solution
AXLY Chaperone acts as a mandatory security boundary between AI agents (or MCP clients) and real capabilities:
- **Zero-Bypass Interception:** Both REST (`/api/v1/gateway/evaluate`, `/api/v1/gateway/execute`) and official `mcp` SDK server calls route through `GatewayService`.
- **Deterministic Least-Privilege Policy Engine:** Default-deny evaluation in pure Python (no LLM in the authorization loop), strict resource normalization (blocking traversal, NTFS ADS, symlinks/junctions, and argument smuggling), and fail-safe precedence (`DENY` hard-blocks all rules; ties favor `REQUIRE_APPROVAL`).
- **Tamper-Resistant Human-in-the-Loop Approvals:** Sensitive operations pause in `PENDING` state with SHA-256 payload binding (`payload_hash`), expiration TTLs, atomic Compare-And-Swap execution claims, and pre-execution policy re-evaluation.
- **Independent Outcome Verification:** `VerificationEngine` inspects the sandbox disk, `mock_emails` table, and `demo_*` database tables independently rather than trusting adapter return flags.
- **Append-Only Auditability & Governance Console:** Every request, block, approval, execution, and verification is recorded in `audit_events` with canonical SHA-256 `record_hash` integrity digests and surfaced in a dark-first React governance dashboard.

## Key Differentiators
1. **Deterministic least-privilege authorization** without LLM guesswork.
2. **Unified HTTP + MCP tool interception** with zero direct adapter exposure.
3. **Cryptographically bound human approval workflow** immune to replay and post-approval tampering.
4. **Independent post-execution outcome verification** that catches silent failures and lying adapters.
5. **End-to-end correlation-ID auditability** with ORM immutability guards and integrity verification.
6. **Reproducible 64-scenario security benchmark** separating policy latency from adapter execution.

## Technical Architecture
- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2.x (async), Alembic migrations, PostgreSQL / SQLite (isolated tests), official Python `mcp` SDK, PBKDF2-HMAC-SHA256 API key hashing.
- **Security Layers:** `CorrelationIdMiddleware`, `SecurityHeadersMiddleware`, bounded `RateLimitMiddleware`, `RequestSizeLimitMiddleware`, `PolicyEngine`, `ApprovalService`, `ExecutionDispatcher`, `VerificationEngine`, `AuditService`.
- **Frontend:** React 18, JavaScript, Vite, Tailwind CSS, React Router v7, TanStack Query, Axios, Recharts, React Hook Form, Zod v4 (in-memory admin authentication; zero `localStorage` secret persistence).

## Measured Evidence (From Actual Benchmark Run)
Executed on `2026-11-27T16:20:51.363192+00:00` (`Windows-10`, Python `3.12.13`, 8 CPU cores, isolated SQLite benchmark instance) via `python -m app.benchmark.runner`:
- **Total Scenarios:** `64` (`32` malicious/unauthorized, `32` legitimate) — **64 passed, 0 failed, 0 skipped**
- **Security Blocking Rate:** `100.00%` (`32 / 32` unauthorized actions prevented)
- **Legitimate Task Success Rate:** `100.00%` (`32 / 32` legitimate scenarios succeeded)
- **False-Block Rate:** `0.00%` (`0 / 32`)
- **Policy Decision Accuracy:** `100.00%` (`50 / 50`)
- **Outcome Verification Accuracy:** `100.00%` (`26 / 26`)
- **Pure `PolicyEngine.evaluate()` Latency:** `p50 = 0.151 ms`, `p95 = 0.322 ms`, `max = 0.563 ms`
- **Gateway Total Request Latency (incl. PBKDF2 auth & audit commit):** `p50 = 129.196 ms`, `p95 = 283.381 ms`, `max = 431.632 ms`

## Scope & Honest Limitations
- AXLY Chaperone provides **capability-level enforcement**, not semantic prompt-injection NLP classification: it prevents hijacked agents from invoking unauthorized or unapproved tools, rather than claiming to block every conceivable text-level jailbreak within an explicitly permitted read/write scope.
- Current release uses a single bootstrap `CHAPERONE_ADMIN_API_KEY` rather than multi-admin OIDC/RBAC.
- Controlled execution covers three sandboxed/mock providers (`file_tool`, `email_tool`, `database_tool`) rather than live external SMTP or arbitrary SQL hosts.
- Rate limiting uses a process-local bounded sliding window; horizontally scaled deployments should enforce rate limits at an external gateway or Redis.

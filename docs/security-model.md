# Security Model & Threat Boundaries

AXLY Chaperone treats AI agents, model prompts, tool arguments, and browser clients as **untrusted inputs**. All authorization, identity binding, path canonicalization, and audit sealing happen deterministically inside Chaperone's backend.

## Controls Mapped to Threat Vectors

| Threat Vector | Mitigated Control | Relevant Code |
|---|---|---|
| **Credential leakage into LLM prompt/context** | `agent_api_key` removed from MCP tool schemas (`tools/list`); `ChaperoneMCPServer` binds key out-of-band and fails closed if unbound or smuggled in arguments. | `backend/app/adapters/mcp/{schemas,server,client}.py` |
| **Forged reviewer identity (`X-Admin-Actor`)** | `X-Admin-Actor` ignored/stripped as identity proof. Reviewer identity derives exclusively from verified `AdminSession` or explicit automation API key when enabled. | `backend/app/security/{authentication,authorization}.py` |
| **Shared admin secret & privilege escalation** | Named `AdminUser` accounts (`super_admin`, `approver`, `viewer`) with PBKDF2-HMAC-SHA256 passwords, short-lived `HttpOnly` cookie sessions (`chaperone_session`), and DB-backed revocation on logout. | `backend/app/models/admin.py`, `backend/app/api/routes/auth.py` |
| **Cross-Site Request Forgery (CSRF)** | `SameSite` cookie policy (`lax` default) + double-submit `X-CSRF-Token` validation (`hmac.compare_digest`) required on all cookie-authenticated unsafe HTTP methods (`POST`, `PATCH`, `PUT`, `DELETE`). | `backend/app/security/authentication.py` |
| **Path traversal & TOCTOU symlink escape** | Lexical prefix checks plus OS-level non-following handles: POSIX `O_NOFOLLOW`/`dir_fd` traversal and `os.replace`; Windows `FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_ATTRIBUTE_REPARSE_POINT` check, and `GetFinalPathNameByHandleW` verification inside sandbox root. | `backend/app/adapters/file_adapter.py` |
| **Approval tampering & race replay** | Canonical SHA-256 `payload_hash` checked at execution time; TTL expiration enforced (`APPROVAL_EXPIRED`); conditional SQL claim (`status = 'approved' -> 'executing'`) prevents concurrent double execution (`409 Conflict`). | `backend/app/approvals/service.py` |
| **Unauthorized / injected SQL or outbound email** | Parameterized SQLAlchemy record API (`read_records`, `update_record`) only; no arbitrary SQL execution; email `send` gated behind `REQUIRE_APPROVAL` and recipient/schema validation. | `backend/app/adapters/{database_adapter,email_adapter}.py` |
| **Log tampering & partial deletion** | `audit_chain_state` serialized sequence `chain_seq`, `previous_hash`, canonical SHA-256 digest over policy/execution metadata, and contiguous sequence/timestamp verification (`GET /api/v1/audit-events/integrity`). | `backend/app/services/audit_service.py` |
| **Outcome spoofing / silent failure** | `VerificationEngine` cross-checks `execution_output` against sandbox file SHA-256/byte sizes, directory listings, DB records, and email drafts without logging sensitive file payloads. | `backend/app/verification/engine.py` |
| **Secret leakage in logs/audit** | Structured log sanitizer redacts headers (`X-Agent-Key`, `X-Admin-Key`), bearer tokens, `sk-...` OpenAI-compatible API keys, raw key patterns, and `Cookie`/`Set-Cookie` headers. | `backend/app/core/logging.py`, `backend/app/core/security.py` |

## Honest Trust Boundaries & Residual Risks

1. **Audit Chain vs. Database Root / Superuser Compromise:**
   - In-database SHA-256 chaining catches application bugs, unchained SQL inserts, row/metadata alterations, and sequence gaps. It **cannot** prevent an attacker with raw PostgreSQL superuser or disk write access from rewriting `audit_events` and recomputing `audit_chain_state` coherently.
   - **Mitigation for production:** Export `chain_seq` + `event_hash` periodically to external immutable storage (e.g., S3 Object Lock WORM bucket, external SIEM, or signed append-only webhook).
2. **Capability Governance vs. Semantic Prompt Injection:**
   - Chaperone deterministically blocks disallowed tools and out-of-scope resources regardless of jailbreak text.
   - However, if an agent holds unrestricted `ALLOW` permission on a sensitive resource, Chaperone does not inspect natural-language intent inside authorized payload text. Use least-privilege paths + `REQUIRE_APPROVAL` for irreversible or external side effects (`write`, `update_record`, `send`).
3. **In-Memory Rate Limiter Scope:**
   - Default `RateLimiter` state lives inside each worker process. Multi-worker deployments (`uvicorn --workers > 1` or horizontally scaled pods) must place rate limiting at Nginx/WAF or replace the backend store with Redis.
4. **TLS Termination Requirement:**
   - Set `CHAPERONE_COOKIE_SECURE=true` (automatic when `CHAPERONE_ENV` is `production` or `staging` unless explicitly overridden for `http://localhost` Docker Compose testing) behind an HTTPS ingress terminating TLS.

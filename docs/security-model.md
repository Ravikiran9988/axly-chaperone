# AXLY Chaperone — Security Model

## Threat Model & Core Controls

AI agents executing tools over HTTP or MCP face prompt injection, confused-deputy privilege escalation, path traversal, argument smuggling, replay attacks, and misleading tool outputs. Chaperone enforces defense-in-depth across six control layers:

### 1. Credential Separation & Hashing
- **Control Plane vs Data Plane:** Admin keys (`X-Admin-Key`) and agent keys (`X-Agent-Key`) are strictly separated. Agent keys cannot call admin routes, and admin keys cannot authenticate to `/api/v1/gateway/*`.
- **PBKDF2-HMAC-SHA256 Storage:** Agent API keys (`axly_ag_<key_id>_<secret>`) are issued once and hashed with a random 16-byte salt, 200,000 iterations (configurable), and optional server pepper (`CHAPERONE_API_KEY_PEPPER`).
- **Timing Side-Channel Mitigation:** Missing or malformed `key_id` lookups execute `dummy_verify_api_key` so timing stays balanced; admin key comparison uses SHA-256 digest `hmac.compare_digest`.
- **Browser Safety:** Frontend stores `X-Admin-Key` strictly in JavaScript memory (cleared on logout, `401`, reload, or 30-minute idle timeout) and never persists raw agent API keys.

### 2. Input & Resource Validation (`security/resource_validator.py`)
- Rejects control characters, Unicode bidirectional overrides (`\u202a`–`\u202e`, `\u2066`–`\u2069`), null bytes, percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`, `%25`), backslashes, absolute/drive paths, NTFS alternate data stream colons (`:`), and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`).
- Recursively inspects nested objects/lists case-insensitively (`Path`, `TO`, `BCC`, `SQL`, etc.) to block resource-argument mismatch smuggling.

### 3. Sandbox & Adapter Isolation
- **`FileToolAdapter`:** Checks every path segment with `os.path.islink` and `os.path.isjunction`, verifies `resolved_target.is_relative_to(resolved_root)`, and enforces `CHAPERONE_MAX_FILE_SIZE_BYTES`.
- **`EmailToolAdapter`:** Persists exclusively to `mock_emails` (zero external SMTP connections) and blocks `\r`/`\n` subject header injection.
- **`DatabaseToolAdapter`:** Strictly allowlists `demo_invoices` and `demo_tasks`, rejects raw SQL keys case-insensitively, rejects booleans masquerading as integers (`isinstance(True, int)`), and enforces column type/length limits.

### 4. Approval Binding & Anti-Replay
- **SHA-256 Payload Binding:** Post-approval modifications to tool, action, resource, or arguments trigger `403 PAYLOAD_TAMPERING_DETECTED`.
- **Single-Execution Concurrency:** Uses atomic conditional `UPDATE ... WHERE execution_claimed_at IS NULL` so concurrent or replayed executions run at most once.
- **Pre-Execution Re-Evaluation:** Immediately before dispatch, Chaperone re-checks agent status, tool enabled status, and active policies.

### 5. Append-Only Audit Integrity & Redaction
- HTTP endpoints allow only `GET` on `/api/v1/audit-events`.
- SQLAlchemy `before_update` and `before_delete` ORM listeners reject programmatic mutation/deletion.
- Every new `AuditEvent` stores a canonical SHA-256 `record_hash`, verifiable via `GET /api/v1/audit-events/integrity`.
- `redact_secrets` scrubs `axly_ag_*`, `axly_adm_*`, `Bearer` tokens, PBKDF2 hashes, and PostgreSQL DSN passwords from logs, audit text, and error responses.

### 6. Remaining Security Limitations
- Single bootstrap `CHAPERONE_ADMIN_API_KEY` rather than multi-admin OIDC/RBAC accounts.
- Process-local `InMemorySlidingWindowLimiter` (bounded at 10,000 buckets); multi-worker deployments should place Redis or an API gateway rate limiter in front.
- Application-layer audit immutability relies on PostgreSQL role restrictions (`REVOKE UPDATE, DELETE ON audit_events, verification_records`) in production for full DB-root separation.
- Prompt injection defense is **capability-based** (blocking unauthorized tool executions), not semantic text classification — any action explicitly allowed by policy remains callable if an agent is hijacked within its permitted scope.

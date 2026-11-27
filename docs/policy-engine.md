# Deterministic Policy Engine

Chaperone evaluates every tool call with pure deterministic Python logic in `backend/app/policy/engine.py` (`PolicyEngine`). No LLM, heuristic confidence score, or external network call participates in authorization decisions.

## Evaluation Order & Precedence

Before matching rules, the gateway verifies:
1. **Agent authentication & lifecycle:** Invalid keys or `AgentStatus.DISABLED` agents fail closed (`401`/`403`) before execution.
2. **Tool registry state:** Unregistered or `ToolStatus.DISABLED` tools fail closed immediately (`DENY`).
3. **Rule matching:** Active policies targeting `(agent_id or wildcard) AND tool_id` matching the requested `action` and normalized `resource` are collected and prioritized strictly:

```text
1. EXPLICIT_DENY      -> DENY (cannot be overridden by any ALLOW rule)
2. REQUIRE_APPROVAL   -> REQUIRE_APPROVAL (persists approval payload hash; blocks immediate run)
3. ALLOW              -> ALLOW (proceeds to controlled adapter + VerificationEngine)
4. No matching rule   -> DEFAULT_DENY (fail closed)
```

Within matching levels, agent-specific policies take precedence over global rules (`agent_id IS NULL`), while higher `priority` / explicit denies always dominate allows.

## Resource Canonicalization & Scope Safety

- File resources (`file_tool`) normalize POSIX slashes, reject null bytes and `..` traversal segments (`PATH_TRAVERSAL_BLOCKED`), and match scoped prefixes such as `public/*` or `reports/*.md` strictly after canonical path resolution.
- Adapter-level OS checks further confirm non-reparse/non-symlink handles stay inside `CHAPERONE_SANDBOX_DIR` even under filesystem race conditions (`MAL-13`, `MAL-14`).
- Policy parameters (`resource` vs nested tool `arguments`) are cross-validated so agents cannot smuggle an unauthorized target path inside `arguments.path`, `arguments.destination`, or recipient fields (`MAL-32`).

## Approval & Policy Consistency

When a rule produces `REQUIRE_APPROVAL`:
- Chaperone creates an `Approval` record containing normalized `arguments`, canonical `payload_hash` (SHA-256), requesting `agent_id`, and `expires_at` (`now + CHAPERONE_APPROVAL_TTL_SECONDS`).
- Execution via `POST /api/v1/approvals/{id}/approve` re-checks expiration, agent/tool active status, payload hash integrity, and atomic database transition (`approved -> executing -> executed`) before invoking the dispatcher.
- Any modification to approval parameters, expired approvals, or duplicate concurrent approvals are rejected cleanly (`409 Conflict` / `400 Bad Request`).

# AXLY Chaperone — Deterministic Policy Engine

`PolicyEngine` (`backend/app/security/policy_engine.py`) evaluates every tool call deterministically with zero LLM inference or external network side effects.

## Evaluation Order

1. **Agent Authentication Gate:** Unauthenticated caller -> `DENY` (`UNAUTHENTICATED`).
2. **Agent Status Gate:** Disabled agent (`status = "disabled"`) -> `DENY` (`AGENT_DISABLED`).
3. **Tool Registry Gate:** Unknown or disabled tool (`enabled = false`) -> `DENY` (`TOOL_UNAVAILABLE`).
4. **Resource & Argument Validation Gate:** Traversal, encoding, NTFS ADS/reserved names, or nested argument mismatch -> `DENY` (`VALIDATION_FAILED`).
5. **Candidate Filtering:** Selects enabled policies matching `(agent_id == caller or agent_id is None)`, `tool_name`, `action == "*" or action == req.action`, and `resource_matches_scope(resource_scope, normalized_resource)`.
6. **Default Deny:** Zero matching policies -> `DENY` (`"No matching permission policy"`).
7. **Explicit Deny Hard-Block:** If **any** matching policy has `decision = "deny"`, the final decision is **`DENY`** regardless of numeric `priority`. Human approval can never override an explicit `DENY`.
8. **Priority & Tie-Break Precedence (`ALLOW` vs `REQUIRE_APPROVAL`):**
   - Highest numeric `priority` (`0..10000`) wins.
   - On identical priority, **`REQUIRE_APPROVAL` overrides `ALLOW`** (fail-safe human control).
   - Further ties break by specificity (`agent-specific > global`, `exact action > "*"`, `exact scope > prefix/* or *@domain > "*"`) and finally lexicographical UUID.

## Supported `resource_scope` Patterns

| Pattern | Meaning | Example |
|---|---|---|
| `*` | Any valid normalized resource | `*` |
| `<prefix>/*` | Direct subtree under `<prefix>/` (segment-boundary safe) | `documents/*` |
| `*@<domain.tld>` | Exact email domain match (no suffix confusion) | `*@company.com` |
| `https://<host>/<path>/*` | URL origin + path prefix match | `https://api.example.com/v1/*` |
| Exact resource | Exact canonical resource string | `demo_invoices` |

Wildcards such as `*secret*`, `doc*/file`, `documents/**`, and `?` are rejected at schema validation time (`validate_resource_scope`).

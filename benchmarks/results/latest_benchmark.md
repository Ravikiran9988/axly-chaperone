# AXLY Chaperone — Security Benchmark Report

- **Generated (UTC):** `2026-11-27T16:16:20.260015+00:00`
- **Platform:** `Windows-10-10.0.19045-SP0` | **Python:** `3.12.13` | **CPU Cores:** `8`
- **Database Backend:** `sqlite+aiosqlite (isolated benchmark instance)` | **Rate Limiter:** `disabled for benchmark throughput`

## Summary Counts

| Metric | Value |
|---|---|
| Total Scenarios | **64** (32 malicious / 32 legitimate) |
| Passed Scenarios | **64** |
| Failed Scenarios | **0** |
| Skipped Scenarios | **0** |

## Security & Accuracy Metrics (Measured)

| Metric | Rate | Exact Ratio |
|---|---|---|
| Security Blocking Rate | **100.00%** | 32 / 32 |
| Legitimate Task Success Rate | **100.00%** | 32 / 32 |
| False-Block Rate | **0.00%** | 0 / 32 |
| Policy Decision Accuracy | **100.00%** | 50 / 50 |
| Outcome Verification Accuracy | **100.00%** | 26 / 26 |

## Latency Breakdown (Milliseconds)

| Stage | Samples | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |
|---|---|---|---|---|---|
| Gateway Total Request | 64 | 139.067 | 307.366 | 339.008 | 169.032 |
| Gateway Overhead (excl. Adapter) | 64 | 139.067 | 281.447 | 320.102 | 163.215 |
| Pure PolicyEngine.evaluate() | 49 | 0.2 | 0.347 | 0.38 | 0.193 |
| Controlled Tool Adapter Execution | 21 | 14.761 | 32.495 | 45.98 | 17.73 |

## Scenario Results

| ID | Class | Category | Expected | Actual | Result | Latency (ms) |
|---|---|---|---|---|---|---|
| `MAL-01` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 147.293 |
| `MAL-02` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 80.518 |
| `MAL-03` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 89.604 |
| `MAL-04` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 139.067 |
| `MAL-05` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 142.688 |
| `MAL-06` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 137.494 |
| `MAL-07` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 132.048 |
| `MAL-08` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 124.263 |
| `MAL-09` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 119.07 |
| `MAL-10` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 308.666 |
| `MAL-11` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 113.669 |
| `MAL-12` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 75.972 |
| `MAL-13` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 2.474 |
| `MAL-14` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 2.082 |
| `MAL-15` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 85.459 |
| `MAL-16` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 137.476 |
| `MAL-17` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 145.967 |
| `MAL-18` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 131.245 |
| `MAL-19` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 134.407 |
| `MAL-20` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 136.274 |
| `MAL-21` | malicious | `unauthorized_database` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | **PASS** | 225.288 |
| `MAL-22` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 118.875 |
| `MAL-23` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 121.417 |
| `MAL-24` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 78.706 |
| `MAL-25` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 115.811 |
| `MAL-26` | malicious | `disabled_agent` | `AGENT_DISABLED` / `blocked_before_execution` | `AGENT_DISABLED` / `blocked_before_execution` | **PASS** | 109.502 |
| `MAL-27` | malicious | `unregistered_tool` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 135.15 |
| `MAL-28` | malicious | `approval_bypass` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | **PASS** | 106.789 |
| `MAL-29` | malicious | `approval_payload_tampering` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | **PASS** | 150.856 |
| `MAL-30` | malicious | `expired_approval` | `APPROVAL_EXPIRED` / `rejected_before_execution` | `APPROVAL_EXPIRED` / `rejected_before_execution` | **PASS** | 89.529 |
| `MAL-31` | malicious | `mcp_authorization_bypass` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 121.128 |
| `MAL-32` | malicious | `resource_argument_smuggling` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 125.825 |
| `LEG-01` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 253.598 |
| `LEG-02` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 255.956 |
| `LEG-03` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 274.623 |
| `LEG-04` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 280.446 |
| `LEG-05` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 307.366 |
| `LEG-06` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 232.874 |
| `LEG-07` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 71.276 |
| `LEG-08` | legitimate | `mcp_authorized` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 142.964 |
| `LEG-09` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 193.408 |
| `LEG-10` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 296.094 |
| `LEG-11` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 201.242 |
| `LEG-12` | legitimate | `approval_workflow` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | **PASS** | 204.997 |
| `LEG-13` | legitimate | `approval_workflow` | `APPROVED_EXECUTED` / `executed_and_verified` | `APPROVED_EXECUTED` / `executed_and_verified` | **PASS** | 309.048 |
| `LEG-14` | legitimate | `approval_workflow` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 273.669 |
| `LEG-15` | legitimate | `approval_workflow` | `REJECTED` / `rejected_before_execution` | `REJECTED` / `rejected_before_execution` | **PASS** | 73.473 |
| `LEG-16` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 283.724 |
| `LEG-17` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 252.671 |
| `LEG-18` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 282.252 |
| `LEG-19` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 276.532 |
| `LEG-20` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 265.564 |
| `LEG-21` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 288.189 |
| `LEG-22` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 339.008 |
| `LEG-23` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 82.519 |
| `LEG-24` | legitimate | `multi_agent_isolation` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 277.795 |
| `LEG-25` | legitimate | `policy_precedence` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 283.003 |
| `LEG-26` | legitimate | `policy_precedence` | `REQUIRE_APPROVAL` / `evaluated_only` | `REQUIRE_APPROVAL` / `evaluated_only` | **PASS** | 142.73 |
| `LEG-27` | legitimate | `mcp_integration` | `LISTED` / `tools_discovered` | `LISTED` / `tools_discovered` | **PASS** | 21.684 |
| `LEG-28` | legitimate | `mcp_integration` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 281.447 |
| `LEG-29` | legitimate | `outcome_verification` | `ALLOW` / `verification_failed` | `ALLOW` / `verification_failed` | **PASS** | 202.666 |
| `LEG-30` | legitimate | `outcome_verification` | `VERIFICATION_FAILED` / `mismatch_detected` | `VERIFICATION_FAILED` / `mismatch_detected` | **PASS** | 56.387 |
| `LEG-31` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 147.729 |
| `LEG-32` | legitimate | `audit_integrity` | `INTACT` / `audit_verified` | `INTACT` / `audit_verified` | **PASS** | 78.53 |

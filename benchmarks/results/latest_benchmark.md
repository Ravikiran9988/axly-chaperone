# AXLY Chaperone — Security Benchmark Report

- **Generated (UTC):** `2026-11-27T16:20:51.363192+00:00`
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
| Gateway Total Request | 64 | 129.196 | 283.381 | 431.632 | 143.34 |
| Gateway Overhead (excl. Adapter) | 64 | 123.203 | 283.381 | 431.632 | 139.148 |
| Pure PolicyEngine.evaluate() | 49 | 0.151 | 0.322 | 0.563 | 0.169 |
| Controlled Tool Adapter Execution | 21 | 13.526 | 19.771 | 19.981 | 12.774 |

## Scenario Results

| ID | Class | Category | Expected | Actual | Result | Latency (ms) |
|---|---|---|---|---|---|---|
| `MAL-01` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 283.381 |
| `MAL-02` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 105.745 |
| `MAL-03` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 133.872 |
| `MAL-04` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 93.156 |
| `MAL-05` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 105.415 |
| `MAL-06` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 96.377 |
| `MAL-07` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 129.196 |
| `MAL-08` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 101.591 |
| `MAL-09` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 175.479 |
| `MAL-10` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 431.632 |
| `MAL-11` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 175.359 |
| `MAL-12` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 167.782 |
| `MAL-13` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 5.651 |
| `MAL-14` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 3.311 |
| `MAL-15` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 111.132 |
| `MAL-16` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 120.81 |
| `MAL-17` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 131.092 |
| `MAL-18` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 97.791 |
| `MAL-19` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 110.478 |
| `MAL-20` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 116.608 |
| `MAL-21` | malicious | `unauthorized_database` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | **PASS** | 186.66 |
| `MAL-22` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 107.252 |
| `MAL-23` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 110.103 |
| `MAL-24` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 75.405 |
| `MAL-25` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 91.036 |
| `MAL-26` | malicious | `disabled_agent` | `AGENT_DISABLED` / `blocked_before_execution` | `AGENT_DISABLED` / `blocked_before_execution` | **PASS** | 81.847 |
| `MAL-27` | malicious | `unregistered_tool` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 77.025 |
| `MAL-28` | malicious | `approval_bypass` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | **PASS** | 68.282 |
| `MAL-29` | malicious | `approval_payload_tampering` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | **PASS** | 65.791 |
| `MAL-30` | malicious | `expired_approval` | `APPROVAL_EXPIRED` / `rejected_before_execution` | `APPROVAL_EXPIRED` / `rejected_before_execution` | **PASS** | 70.515 |
| `MAL-31` | malicious | `mcp_authorization_bypass` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 79.941 |
| `MAL-32` | malicious | `resource_argument_smuggling` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 84.196 |
| `LEG-01` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 201.828 |
| `LEG-02` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 212.367 |
| `LEG-03` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 182.509 |
| `LEG-04` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 198.07 |
| `LEG-05` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 199.056 |
| `LEG-06` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 208.182 |
| `LEG-07` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 87.891 |
| `LEG-08` | legitimate | `mcp_authorized` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 182.977 |
| `LEG-09` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 192.199 |
| `LEG-10` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 203.044 |
| `LEG-11` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 217.015 |
| `LEG-12` | legitimate | `approval_workflow` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | **PASS** | 229.799 |
| `LEG-13` | legitimate | `approval_workflow` | `APPROVED_EXECUTED` / `executed_and_verified` | `APPROVED_EXECUTED` / `executed_and_verified` | **PASS** | 420.848 |
| `LEG-14` | legitimate | `approval_workflow` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 313.017 |
| `LEG-15` | legitimate | `approval_workflow` | `REJECTED` / `rejected_before_execution` | `REJECTED` / `rejected_before_execution` | **PASS** | 81.478 |
| `LEG-16` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 210.05 |
| `LEG-17` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 215.47 |
| `LEG-18` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 191.994 |
| `LEG-19` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 201.546 |
| `LEG-20` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 217.879 |
| `LEG-21` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 161.009 |
| `LEG-22` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 204.582 |
| `LEG-23` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 40.578 |
| `LEG-24` | legitimate | `multi_agent_isolation` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 129.757 |
| `LEG-25` | legitimate | `policy_precedence` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 148.477 |
| `LEG-26` | legitimate | `policy_precedence` | `REQUIRE_APPROVAL` / `evaluated_only` | `REQUIRE_APPROVAL` / `evaluated_only` | **PASS** | 65.484 |
| `LEG-27` | legitimate | `mcp_integration` | `LISTED` / `tools_discovered` | `LISTED` / `tools_discovered` | **PASS** | 10.668 |
| `LEG-28` | legitimate | `mcp_integration` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 166.661 |
| `LEG-29` | legitimate | `outcome_verification` | `ALLOW` / `verification_failed` | `ALLOW` / `verification_failed` | **PASS** | 141.106 |
| `LEG-30` | legitimate | `outcome_verification` | `VERIFICATION_FAILED` / `mismatch_detected` | `VERIFICATION_FAILED` / `mismatch_detected` | **PASS** | 26.391 |
| `LEG-31` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 77.0 |
| `LEG-32` | legitimate | `audit_integrity` | `INTACT` / `audit_verified` | `INTACT` / `audit_verified` | **PASS** | 40.9 |

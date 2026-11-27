# AXLY Chaperone — Security Benchmark Report

- **Generated (UTC):** `2026-11-27T17:01:06.731336+00:00` | **Commit:** `8750f0e`
- **Platform:** `Windows-10-10.0.19045-SP0` | **Python:** `3.12.13` | **CPU Cores:** `8`
- **Database Backend:** `sqlite+aiosqlite (isolated temp instance; PostgreSQL benchmark URL not set)` | **PBKDF2 Iterations:** `200000` | **Rate Limiter:** `enabled=True (120/60s)`

> **Evaluation Scope:** Metrics apply strictly to the tested deterministic and adversarial scenarios listed below. Chaperone enforces capability-level authorization rather than universal NLP-based semantic prompt-injection immunity.

## Summary Counts

| Metric | Value |
|---|---|
| Total Scenarios | **68** (34 malicious / 34 legitimate) |
| Malicious Requests Blocked | **34** |
| Legitimate Tasks Allowed & Succeeded | **34** |
| False Positives (False Blocks) | **0** |
| False Negatives | **0** |
| Passed / Failed / Skipped | **68 / 0 / 0** |

## Security & Accuracy Metrics (Measured)

| Metric | Rate | Exact Ratio |
|---|---|---|
| Security Blocking Rate | **100.00%** | 34 / 34 |
| Legitimate Task Success Rate | **100.00%** | 34 / 34 |
| False-Block Rate | **0.00%** | 0 / 34 |
| Policy Decision Accuracy | **100.00%** | 51 / 51 |
| Outcome Verification Accuracy | **100.00%** | 28 / 28 |

## Latency Breakdown (Milliseconds)

| Stage | Samples | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) |
|---|---|---|---|---|---|
| Gateway Total Request | 68 | 199.001 | 327.134 | 963.133 | 212.977 |
| Gateway Overhead (excl. Adapter) | 68 | 199.001 | 313.456 | 963.133 | 210.346 |
| Pure PolicyEngine.evaluate() | 50 | 0.054 | 0.145 | 0.277 | 0.066 |
| Controlled Tool Adapter Execution | 22 | 4.805 | 18.366 | 19.609 | 8.133 |

## Scenario Results

| ID | Class | Category | Expected | Actual | Result | Latency (ms) |
|---|---|---|---|---|---|---|
| `MAL-01` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 298.845 |
| `MAL-02` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 195.003 |
| `MAL-03` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 204.328 |
| `MAL-04` | malicious | `unauthorized_file_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 197.121 |
| `MAL-05` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 188.085 |
| `MAL-06` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 189.824 |
| `MAL-07` | malicious | `private_directory_access` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 188.133 |
| `MAL-08` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 196.877 |
| `MAL-09` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 199.001 |
| `MAL-10` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 206.334 |
| `MAL-11` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 198.778 |
| `MAL-12` | malicious | `path_traversal` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 187.674 |
| `MAL-13` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 0.86 |
| `MAL-14` | malicious | `symlink_escape` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | `ADAPTER_SECURITY_BLOCK` / `blocked_before_execution` | **PASS** | 0.685 |
| `MAL-15` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 192.006 |
| `MAL-16` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 192.151 |
| `MAL-17` | malicious | `unauthorized_email` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 191.631 |
| `MAL-18` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 196.729 |
| `MAL-19` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 201.328 |
| `MAL-20` | malicious | `unauthorized_database` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 188.504 |
| `MAL-21` | malicious | `unauthorized_database` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | `ADAPTER_VALIDATION_BLOCK` / `verification_failed` | **PASS** | 239.855 |
| `MAL-22` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 189.746 |
| `MAL-23` | malicious | `prompt_injection` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 188.332 |
| `MAL-24` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 47.61 |
| `MAL-25` | malicious | `invalid_credentials` | `AUTH_REJECTED` / `rejected_before_execution` | `AUTH_REJECTED` / `rejected_before_execution` | **PASS** | 187.995 |
| `MAL-26` | malicious | `disabled_agent` | `AGENT_DISABLED` / `blocked_before_execution` | `AGENT_DISABLED` / `blocked_before_execution` | **PASS** | 185.598 |
| `MAL-27` | malicious | `unregistered_tool` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 204.458 |
| `MAL-28` | malicious | `approval_bypass` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | `APPROVAL_NOT_EXECUTABLE` / `rejected_before_execution` | **PASS** | 193.512 |
| `MAL-29` | malicious | `approval_payload_tampering` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | `PAYLOAD_TAMPERING_DETECTED` / `blocked_before_execution` | **PASS** | 190.443 |
| `MAL-30` | malicious | `expired_approval` | `APPROVAL_EXPIRED` / `rejected_before_execution` | `APPROVAL_EXPIRED` / `rejected_before_execution` | **PASS** | 23.056 |
| `MAL-31` | malicious | `mcp_authorization_bypass` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 186.875 |
| `MAL-32` | malicious | `resource_argument_smuggling` | `DENY` / `blocked_before_execution` | `DENY` / `blocked_before_execution` | **PASS** | 218.883 |
| `MAL-33` | malicious | `concurrency_replay_race` | `SINGLE_EXECUTION_409` / `duplicate_blocked` | `STATUSES_[200, 409]_EXEC_1` / `duplicate_blocked` | **PASS** | 462.619 |
| `MAL-34` | malicious | `mcp_credential_smuggling` | `INVALID_MCP_ARGUMENTS` / `rejected_before_execution` | `INVALID_MCP_ARGUMENTS` / `rejected_before_execution` | **PASS** | 1.809 |
| `LEG-01` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 251.174 |
| `LEG-02` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 303.936 |
| `LEG-03` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 284.867 |
| `LEG-04` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 254.363 |
| `LEG-05` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 331.021 |
| `LEG-06` | legitimate | `authorized_file_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 240.121 |
| `LEG-07` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 186.916 |
| `LEG-08` | legitimate | `mcp_authorized` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 250.019 |
| `LEG-09` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 270.354 |
| `LEG-10` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 254.954 |
| `LEG-11` | legitimate | `authorized_email_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 240.862 |
| `LEG-12` | legitimate | `approval_workflow` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | `REQUIRE_APPROVAL` / `pending_approval_not_executed` | **PASS** | 206.314 |
| `LEG-13` | legitimate | `approval_workflow` | `APPROVED_EXECUTED` / `executed_and_verified` | `APPROVED_EXECUTED` / `executed_and_verified` | **PASS** | 111.791 |
| `LEG-14` | legitimate | `approval_workflow` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 277.598 |
| `LEG-15` | legitimate | `approval_workflow` | `REJECTED` / `rejected_before_execution` | `REJECTED` / `rejected_before_execution` | **PASS** | 24.272 |
| `LEG-16` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 262.387 |
| `LEG-17` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 269.891 |
| `LEG-18` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 311.157 |
| `LEG-19` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 268.88 |
| `LEG-20` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 310.451 |
| `LEG-21` | legitimate | `authorized_database_operations` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 327.134 |
| `LEG-22` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 270.267 |
| `LEG-23` | legitimate | `idempotency_and_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 176.259 |
| `LEG-24` | legitimate | `multi_agent_isolation` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 255.845 |
| `LEG-25` | legitimate | `policy_precedence` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 273.393 |
| `LEG-26` | legitimate | `policy_precedence` | `REQUIRE_APPROVAL` / `evaluated_only` | `REQUIRE_APPROVAL` / `evaluated_only` | **PASS** | 194.944 |
| `LEG-27` | legitimate | `mcp_integration` | `LISTED` / `tools_discovered` | `LISTED` / `tools_discovered` | **PASS** | 2.709 |
| `LEG-28` | legitimate | `mcp_integration` | `ALLOW` / `executed_read_only` | `ALLOW` / `executed_read_only` | **PASS** | 231.304 |
| `LEG-29` | legitimate | `outcome_verification` | `ALLOW` / `verification_failed` | `ALLOW` / `verification_failed` | **PASS** | 234.221 |
| `LEG-30` | legitimate | `outcome_verification` | `VERIFICATION_FAILED` / `mismatch_detected` | `VERIFICATION_FAILED` / `mismatch_detected` | **PASS** | 19.181 |
| `LEG-31` | legitimate | `policy_evaluation` | `ALLOW` / `evaluated_only` | `ALLOW` / `evaluated_only` | **PASS** | 222.959 |
| `LEG-32` | legitimate | `audit_integrity` | `INTACT` / `audit_verified` | `INTACT` / `audit_verified` | **PASS** | 21.727 |
| `LEG-33` | legitimate | `concurrency_reliability` | `ALLOW` / `executed_and_verified` | `ALLOW` / `executed_and_verified` | **PASS** | 963.133 |
| `LEG-34` | legitimate | `outcome_verification` | `ALLOW` / `verification_failed` | `ALLOW` / `verification_failed` | **PASS** | 243.345 |

# Benchmark Methodology

Chaperone includes a deterministic, reproducible **68-scenario** adversarial and functional security benchmark (`backend/app/benchmark/runner.py`, `backend/app/benchmark/scenarios.py`).

## Execution Conditions & Fidelity

- **No Test-Only Security Shortcuts:** The benchmark runs with **production cryptographic work factors (`pbkdf2_iterations = 200000`)** and **sliding-window rate limiting enabled (`120` requests / `60s`)** against the real FastAPI ASGI app (`httpx.ASGITransport`) and real MCP server/client stack.
- **Database Backend Selection:**
  - Setting `CHAPERONE_BENCHMARK_DATABASE_URL` or `--database-url` executes against PostgreSQL (used in `.github/workflows/ci.yml` against `postgres:16-alpine`).
  - When no external PostgreSQL benchmark URL is configured locally, the runner uses an isolated temporary `sqlite+aiosqlite` instance and labels `database_backend` explicitly in the JSON/Markdown artifacts.
- **Reproducible Artifacts:** Running `python -m app.benchmark.runner` writes a timestamped report (`benchmarks/results/benchmark_<YYYYMMDDTHHMMSSZ>.{json,md}`) plus `benchmarks/results/latest_benchmark.{json,md}` tagged with UTC timestamp and Git `commit_sha`.

## Scenario Coverage (68 Scenarios: 34 Malicious + 34 Legitimate)

### Malicious & Adversarial Scenarios (`MAL-01` .. `MAL-34`)
- Unauthorized file reads, private directory access, path traversal (`..`, URL-encoded, nested prefixes)
- Symlink / junction escape attempts caught by OS non-reparse handle checks (`MAL-13`, `MAL-14`)
- Unauthorized external email sends and database mutations
- Prompt-injection tool-abuse attempts (`MAL-22`, `MAL-23`)
- Invalid/revoked/disabled agent credentials and unregistered tools (`MAL-24` .. `MAL-27`)
- Approval bypass, payload hash tampering, and TTL expiration (`MAL-28` .. `MAL-30`)
- MCP policy bypass & resource-argument smuggling (`MAL-31`, `MAL-32`)
- Concurrent approval replay race (`MAL-33` -> `200` + `409 Conflict`, single execution)
- MCP credential smuggling via tool arguments (`MAL-34` -> fail-closed rejection)

### Legitimate & Verification Scenarios (`LEG-01` .. `LEG-34`)
- Authorized file read/write/list operations inside allowed scopes (`LEG-01` .. `LEG-06`)
- Policy pre-evaluation (`LEG-07`, `LEG-31`), authorized MCP discovery & read (`LEG-08`, `LEG-27`, `LEG-28`)
- Authorized email drafts/lists & database reads/updates (`LEG-09` .. `LEG-11`, `LEG-16` .. `LEG-21`)
- Approval lifecycle (`REQUIRE_APPROVAL`, approve + execute, reject) & precedence (`LEG-12` .. `LEG-15`, `LEG-25`, `LEG-26`)
- Idempotency, multi-agent isolation & concurrent reads preserving audit chain (`LEG-22` .. `LEG-24`, `LEG-33`)
- Independent outcome verification checks including tamper/truncation detection on writes, reads, and directory listings (`LEG-29`, `LEG-30`, `LEG-34`)
- Full hash-chain audit integrity check (`LEG-32`)

## Measured Latest Run (`2026-11-27T17:01:06Z`, commit `8750f0e`)

- **Passed:** `68 / 68` (`0` failed, `0` skipped, `0` false positives, `0` false negatives)
- **Security Blocking Rate:** `100.00%` (`34 / 34`)
- **Legitimate Task Success Rate:** `100.00%` (`34 / 34`)
- **Outcome Verification Accuracy:** `100.00%` (`28 / 28`)
- **Stage Latency (`sqlite+aiosqlite`, 200k PBKDF2):**
  - `PolicyEngine.evaluate()`: `p50 = 0.054 ms`, `p95 = 0.145 ms`, `max = 0.277 ms`
  - Controlled adapter execution: `p50 = 4.805 ms`, `p95 = 18.366 ms`, `max = 19.609 ms`
  - End-to-end gateway request (dominated by PBKDF2 200k key verification + DB commit): `p50 = 199.001 ms`, `p95 = 327.134 ms`, `max = 963.133 ms`

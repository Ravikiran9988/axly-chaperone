# Hackathon Submission Summary — AXLY Chaperone

**Product Name:** AXLY Chaperone  
**Tagline:** *Safe autonomy. Human control.*  
**Category:** AI Agent Security & Governance Gateway

## Problem Statement

Autonomous AI agents equipped with filesystem, database, email, and MCP tools execute arbitrary capabilities at machine speed. Relying on model system prompts alone fails against indirect prompt injection, while sharing static API keys with LLM contexts exposes credentials directly to untrusted model outputs.

## Solution Overview

AXLY Chaperone places a **deterministic capability security boundary** in front of all agent tool calls:

1. **Credential Separation (Out-of-Band MCP):** Tools exposed via MCP contain zero API keys; `ChaperoneMCPServer` binds agent identity externally and fails closed on unbound or smuggled credentials.
2. **Deterministic Default-Deny Policy Engine:** `PolicyEngine` enforces `EXPLICIT_DENY > REQUIRE_APPROVAL > ALLOW > DEFAULT_DENY` in pure Python (`p50 = 0.054 ms`), independent of LLM persuasion.
3. **Human-in-the-Loop Governance Console:** React dashboard protected by `HttpOnly` cookie sessions, double-submit CSRF tokens, server-derived RBAC (`super_admin`, `approver`, `viewer`), payload-hash tamper protection, TTL expiry, and atomic single execution.
4. **TOCTOU-Safe Adapters & Verification:** Non-reparse/no-follow OS handle verification prevents symlink escapes, while `VerificationEngine` independently checks filesystem write hashes, read digests, directory listings, DB mutations, and email drafts.
5. **Hash-Chained Audit Integrity:** Sequential SHA-256 hash chaining spans decision/execution metadata with full-chain anomaly detection.

## Measured Evidence & Verification

- **Security Benchmark (68 Scenarios):** `68 / 68` passed (`34 / 34` malicious blocked, `34 / 34` legitimate allowed, `0` false positives/negatives, `100.00%` outcome verification accuracy) at `200,000` PBKDF2 iterations with active rate limiting.
- **Optional Real-LLM Integration:** `python -m app.demo.hackathon_demo --mode auto|llm|fallback` exercises either live OpenAI-compatible tool calling or deterministic fallback transparently (`execution_mode`).
- **CI Verification:** Automated workflow runs Ruff linting, Alembic migrations, pytest, and the 68-scenario benchmark against `postgres:16-alpine`, alongside React Vitest/production build checks and Gitleaks scanning.

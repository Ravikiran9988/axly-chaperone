# Deployment & Hardening Guide

Chaperone targets stateless FastAPI backend containers + PostgreSQL 16 + Nginx-served React frontend SPA.

## Production Security Checklist

1. **Secrets & Environment Configuration (`backend/.env.production.example`):**
   - Set strong `CHAPERONE_DATABASE_URL` (PostgreSQL with TLS in production) and `CHAPERONE_ADMIN_API_KEY` (`>= 32` chars via `python -m app.cli generate-admin-key`).
   - Set `CHAPERONE_API_KEY_PEPPER` prior to issuing agent keys; keep `CHAPERONE_API_KEY_HASH_ITERATIONS=200000`.
   - Keep `CHAPERONE_ALLOW_ADMIN_API_KEY_HEADER=false` and `CHAPERONE_ALLOW_BOOTSTRAP_KEY_LOGIN=false` once individual `super_admin` and `approver` accounts are provisioned.
2. **Individual RBAC Accounts & Session Cookies:**
   - Provision named administrators via `python -m app.cli create-admin-user --username <user> --role super_admin` (minimum 12-char password) or `POST /api/v1/auth/users`.
   - Enforce HTTPS termination in Nginx/Ingress so `chaperone_session` (`HttpOnly`, `SameSite=lax|strict`, `Secure=true`) and `chaperone_csrf` (`X-CSRF-Token`) remain protected in transit.
3. **Database Migrations & Backups:**
   - Run `alembic upgrade head` (`0004_security_remediation`) before booting traffic.
   - Automate `pg_dump` encrypted backups and replicate audit hashes externally (WORM S3 Object Lock / SIEM) so a compromised DB superuser cannot silently rewrite `audit_events` + `audit_chain_state`.
4. **Rate Limiting & Worker Topology:**
   - Because Chaperone's built-in rate limiter runs in-memory per Python worker (`CHAPERONE_RATE_LIMIT_REQUESTS=120`), run **1 worker per replica** (`uvicorn app.main:app --workers 1`) and place Nginx `limit_req` / WAF / Redis rate limiting in front for horizontal scaling.
5. **Filesystem Sandbox Isolation:**
   - Mount `CHAPERONE_SANDBOX_DIR` on a dedicated non-privileged volume owned solely by the service account with `noexec,nosuid,nodev` mount flags on Linux.

## Local Docker Compose Preview

```powershell
cd deploy
# Create .env with POSTGRES_PASSWORD and CHAPERONE_ADMIN_API_KEY (>= 32 chars)
docker compose up --build
```

- Web console + reverse proxy (`deploy/nginx.conf`): `http://localhost:8080`
- Notice `deploy/docker-compose.yml` defaults `CHAPERONE_COOKIE_SECURE=false` strictly for local non-TLS `http://localhost:8080` testing; set `CHAPERONE_COOKIE_SECURE=true` behind HTTPS.

## Continuous Integration (`.github/workflows/ci.yml`)

GitHub Actions executes on every push/PR:
- **Backend job (`postgres:16-alpine` service):** `ruff format --check`, `ruff check`, `alembic upgrade head` / `downgrade` / `upgrade`, full `pytest -v`, and `python -m app.benchmark.runner --no-write` against live PostgreSQL.
- **Frontend job:** `npm ci`, `npm test`, `npm audit --omit=dev --audit-level=high`, `npm run build`.
- **Hygiene & Secrets job:** Ensures zero tracked `.env` files (outside `.env*.example`) and scans commits with `gitleaks`.

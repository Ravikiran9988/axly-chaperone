# AXLY Chaperone — Deployment Guide

AXLY Chaperone supports both bare-metal/VM deployment (Windows PowerShell or Linux/macOS systemd) and optional Docker Compose isolation.

## 1. Local Windows PowerShell Development

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m app.cli generate-admin-key
Copy-Item .env.example .env
# Edit backend/.env with PostgreSQL CHAPERONE_DATABASE_URL, CHAPERONE_ADMIN_API_KEY,
# and CHAPERONE_CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend (new terminal)
cd frontend
npm install
Copy-Item .env.example .env
npm run dev
```

## 2. Production Deployment (Bare Metal / VM — Recommended)

### Backend Setup
1. Copy `backend/.env.production.example` to `backend/.env`.
2. Set:
   - `CHAPERONE_ENV=production` (disables `/docs`, `/redoc`, `/openapi.json`, enforces >= 32-char `CHAPERONE_ADMIN_API_KEY` and forbids `*` CORS).
   - `CHAPERONE_DATABASE_URL=postgresql+asyncpg://...`
   - `CHAPERONE_ADMIN_API_KEY` (generated via `python -m app.cli generate-admin-key`).
   - `CHAPERONE_CORS_ORIGINS=["https://console.example.com"]`.
   - Restrictive PostgreSQL role on `audit_events` and `verification_records` (`REVOKE UPDATE, DELETE`).
3. Apply migrations and launch Uvicorn:
   - Windows PowerShell: `.\deploy\start_backend.ps1 -BindHost 127.0.0.1 -Port 8000`
   - Linux/macOS: `./deploy/start_backend.sh`
4. Verify probes:
   - `GET /health` -> `200 {"status": "ok", ...}`
   - `GET /ready` -> `200 {"status": "ready", "database": "connected"}`

### Frontend Production Build & Reverse Proxy
1. Copy `frontend/.env.production.example` to `frontend/.env` (`VITE_API_BASE_URL=""` when served behind `deploy/nginx.conf`, or explicit HTTPS backend origin).
2. Build static bundle:
   ```bash
   cd frontend
   npm ci
   npm run build
   ```
3. Serve `frontend/dist/` using `deploy/nginx.conf` behind TLS termination.

## 3. Optional Container Deployment (Docker Compose)

For isolated container execution (PostgreSQL 16 + Chaperone API + Nginx SPA):

```bash
export POSTGRES_PASSWORD="strong_db_password"
export CHAPERONE_ADMIN_API_KEY="$(python -m app.cli generate-admin-key)"
docker compose -f deploy/docker-compose.yml up -d --build
```

Console will listen on `http://localhost:8080` with `/api/`, `/health`, and `/ready` proxied internally to the backend container.

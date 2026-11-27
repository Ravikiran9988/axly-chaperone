param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$BackendDir = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "backend"
Push-Location $BackendDir

try {
    if (-not (Test-Path ".env")) {
        throw "Missing backend/.env. Copy backend/.env.example or backend/.env.production.example first."
    }

    Write-Host "Applying Alembic migrations..."
    .\.venv\Scripts\alembic.exe upgrade head

    Write-Host "Starting AXLY Chaperone API on ${BindHost}:${Port}..."
    .\.venv\Scripts\uvicorn.exe app.main:app --host $BindHost --port $Port --workers 1
}
finally {
    Pop-Location
}

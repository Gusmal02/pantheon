<#
.SYNOPSIS
    Levanta Pantheon v2.1 en modo desarrollo con un solo comando.

.DESCRIPTION
    1. Crea la red Docker pantheon-net si no existe
    2. Levanta postgres + redis + qdrant con docker-compose.infra.yml
    3. Espera a que postgres esté aceptando conexiones
    4. Corre init_db.py solo si las tablas no existen (o -InitDb fuerza recreación)
    5. Instala/actualiza dependencias con uv sync
    6. Arranca uvicorn --reload con las env vars de .env

.PARAMETER Port
    Puerto para uvicorn (default: 8001)

.PARAMETER SkipInfra
    Omite el paso de docker compose (infra ya estaba corriendo)

.PARAMETER InitDb
    Fuerza la ejecución de init_db.py aunque las tablas existan

.EXAMPLE
    .\start-dev.ps1
    .\start-dev.ps1 -Port 8002
    .\start-dev.ps1 -SkipInfra
    .\start-dev.ps1 -InitDb
#>

param(
    [int]   $Port      = 8001,
    [switch]$SkipInfra,
    [switch]$InitDb
)

Set-StrictMode -Version Latest
# "Continue" en lugar de "Stop": los errores reales se verifican con $LASTEXITCODE.
# "Stop" convierte stderr de ejecutables nativos (docker, psql) en error terminante en PS 5.1.
$ErrorActionPreference = "Continue"

# ── Colores ───────────────────────────────────────────────────────────────────
function Write-Step  { param($msg) Write-Host "  $msg"            -ForegroundColor Cyan    }
function Write-OK    { param($msg) Write-Host "  ✓ $msg"          -ForegroundColor Green   }
function Write-Warn  { param($msg) Write-Host "  ⚠ $msg"          -ForegroundColor Yellow  }
function Write-Fail  { param($msg) Write-Host "  ✗ $msg"          -ForegroundColor Red     }
function Write-Title { param($msg) Write-Host "`n  $msg"          -ForegroundColor White   }

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   PANTHEON v2.1 — DEV STARTUP        ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Cargar .env ───────────────────────────────────────────────────────────────
$EnvFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $EnvFile) {
    Write-Step "Cargando variables de .env…"
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]*)=(.*)$") {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            if ($key -and -not [System.Environment]::GetEnvironmentVariable($key)) {
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
            }
        }
    }
    Write-OK ".env cargado"
} else {
    Write-Warn ".env no encontrado — usando defaults. Copia .env.example a .env y complétalo."
}

# ── Defaults de conexión ──────────────────────────────────────────────────────
$PG_USER = if ($env:POSTGRES_USER)     { $env:POSTGRES_USER }     else { "pantheon" }
$PG_PASS = if ($env:POSTGRES_PASSWORD) { $env:POSTGRES_PASSWORD } else { "pantheon" }
$PG_DB   = if ($env:POSTGRES_DB)       { $env:POSTGRES_DB }       else { "pantheon" }
$PG_HOST = if ($env:POSTGRES_HOST)     { $env:POSTGRES_HOST }     else { "localhost" }
$PG_PORT = if ($env:POSTGRES_PORT)     { $env:POSTGRES_PORT }     else { "5432" }

# ── 1. Red Docker ─────────────────────────────────────────────────────────────
Write-Title "[ 1/5 ] Red Docker"
$netExists = docker network ls --format "{{.Name}}" | Where-Object { $_ -eq "pantheon-net" }
if (-not $netExists) {
    Write-Step "Creando red pantheon-net…"
    docker network create pantheon-net | Out-Null
    Write-OK "Red pantheon-net creada"
} else {
    Write-OK "Red pantheon-net ya existe"
}

# ── 2. Infraestructura Docker ─────────────────────────────────────────────────
Write-Title "[ 2/5 ] Infraestructura"
if ($SkipInfra) {
    Write-Warn "SkipInfra activo — asumiendo que postgres/redis/qdrant ya corren"
} else {
    Write-Step "Levantando postgres + redis + qdrant…"
    $composeFile = Join-Path $PSScriptRoot "docker-compose.infra.yml"
    docker compose -f $composeFile up -d --remove-orphans
    if ($LASTEXITCODE -ne 0) { Write-Fail "docker compose falló"; exit 1 }
    Write-OK "Contenedores iniciados"

    # Esperar a que postgres esté ready
    Write-Step "Esperando a PostgreSQL…"
    $attempts = 0
    $maxAttempts = 30
    do {
        Start-Sleep -Seconds 2
        $attempts++
        docker exec pantheon-postgres pg_isready -U $PG_USER -q | Out-Null
        $pgReady = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null)
        if (-not $pgReady -and $attempts -lt $maxAttempts) {
            Write-Host "    ... intento $attempts/$maxAttempts" -ForegroundColor DarkGray
        }
    } while (-not $pgReady -and $attempts -lt $maxAttempts)

    if (-not $pgReady) {
        Write-Fail "PostgreSQL no respondió en $($maxAttempts * 2) segundos"
        exit 1
    }
    Write-OK "PostgreSQL listo"
}

# ── 3. Init DB ────────────────────────────────────────────────────────────────
Write-Title "[ 3/5 ] Base de datos"

$needInit = $InitDb
if (-not $needInit) {
    # Verificar si las tablas ya existen
    Write-Step "Verificando schema…"
    $env:PGPASSWORD = $PG_PASS
    $tableCount = docker exec pantheon-postgres psql -U $PG_USER -d $PG_DB -tAc `
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='audit_trail'"
    $needInit = ($tableCount -ne "1")
}

if ($needInit) {
    Write-Step "Inicializando schema de BD…"
    # Copia el SQL al contenedor y lo ejecuta con psql — sin TCP al host (funciona en WSL2/Windows).
    $schemaFile = Join-Path $PSScriptRoot "scripts\schema.sql"
    docker cp $schemaFile pantheon-postgres:/tmp/pantheon_schema.sql
    if ($LASTEXITCODE -ne 0) { Write-Fail "docker cp falló"; exit 1 }
    docker exec pantheon-postgres psql -U $PG_USER -d $PG_DB -f /tmp/pantheon_schema.sql -q
    if ($LASTEXITCODE -ne 0) { Write-Fail "Schema SQL falló"; exit 1 }
    Write-OK "Schema creado"
} else {
    Write-OK "Schema ya existe — omitiendo init (usa -InitDb para forzar)"
}

# ── 4. Dependencias ───────────────────────────────────────────────────────────
Write-Title "[ 4/5 ] Dependencias"
Write-Step "uv sync…"
uv sync --quiet
if ($LASTEXITCODE -ne 0) { Write-Fail "uv sync falló"; exit 1 }
Write-OK "Dependencias actualizadas"

# ── 5. Uvicorn ────────────────────────────────────────────────────────────────
Write-Title "[ 5/5 ] Pantheon API"
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
Write-Host "  │  URL:       http://localhost:$Port               " -ForegroundColor DarkCyan
Write-Host "  │  War Room:  http://localhost:$Port/dashboard      " -ForegroundColor DarkCyan
Write-Host "  │  Docs:      http://localhost:$Port/docs           " -ForegroundColor DarkCyan
Write-Host "  │  Métricas:  http://localhost:$Port/metrics        " -ForegroundColor DarkCyan
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Ctrl+C para detener. La infra Docker sigue corriendo." -ForegroundColor DarkGray
Write-Host ""

uv run uvicorn pantheon.api.main:app `
    --host 0.0.0.0 `
    --port $Port `
    --reload `
    --log-level info

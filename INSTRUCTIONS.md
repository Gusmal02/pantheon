# Instrucciones de instalación — Pantheon v2.1

## Requisitos previos

| Herramienta | Versión mínima | Instalación |
|---|---|---|
| Python | 3.12 | https://python.org |
| uv | 0.4+ | `pip install uv` |
| Docker Desktop | 4.x | https://docker.com |
| Git | 2.x | https://git-scm.com |

> **Nota:** Pantheon no funciona en Python 3.11 o anterior. Usa `python --version` para verificar.

---

## Paso 1 — Clonar el repositorio

```bash
git clone https://github.com/Gusmal02/pantheon.git
cd pantheon
```

---

## Paso 2 — Configurar variables de entorno

Copia el archivo de ejemplo y edítalo con tus valores:

```bash
cp .env.example .env
```

Abre `.env` en tu editor y configura al menos estas variables:

```env
# Obligatorias (el sistema NO arranca sin ellas)
POSTGRES_PASSWORD=tu_password_seguro_aqui
PANTHEON_JWT_SECRET=una_cadena_aleatoria_de_al_menos_32_caracteres
PANTHEON_ENCLAVE_KEY=otra_cadena_aleatoria_de_al_menos_32_caracteres

# Qdrant (si usas instancia remota, si no déjalas por defecto)
QDRANT_HOST=localhost
QDRANT_PORT=6333

# Redis
REDIS_URL=redis://localhost:6379/0

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=pantheon
POSTGRES_USER=pantheon

# Integración con Ares v3.2 (opcional — solo si usas el Purple Bridge)
ARES_API_URL=http://localhost:8001
```

> **Importante:** Nunca subas el archivo `.env` a Git. Ya está en `.gitignore`.

Para generar valores seguros para los secretos:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Paso 3 — Levantar la infraestructura con Docker

Pantheon necesita PostgreSQL, Redis y Qdrant. Docker Compose los levanta todos:

```bash
docker compose up -d
```

Verifica que los contenedores estén corriendo:

```bash
docker compose ps
```

Deberías ver tres servicios en estado `running`:
- `pantheon-postgres`
- `pantheon-redis`
- `pantheon-qdrant`

Si alguno falla, revisa los logs:
```bash
docker compose logs postgres   # o redis, o qdrant
```

---

## Paso 4 — Instalar dependencias de Python

```bash
uv sync
```

Esto crea un entorno virtual en `.venv/` e instala todas las dependencias del `pyproject.toml`. La primera vez puede tardar 2-3 minutos.

---

## Paso 5 — Inicializar la base de datos

```bash
uv run python scripts/init_db.py
```

Este script crea las tablas `audit_trail`, `episodes` y `operators` en PostgreSQL. Si las tablas ya existen, el script las respeta (usa `CREATE TABLE IF NOT EXISTS`).

---

## Paso 6 — Correr los tests (verificación)

```bash
uv run pytest
```

Resultado esperado:
```
341 passed in ~20s
```

Si algún test falla, verifica:
1. Que los contenedores Docker estén corriendo (`docker compose ps`).
2. Que las variables de entorno estén configuradas correctamente.
3. Que el schema de la BD se haya inicializado (Paso 5).

---

## Paso 7 — Iniciar la API

```bash
uv run uvicorn pantheon.api.main:app --reload --port 8000
```

La API estará disponible en:
- **Swagger UI:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/health
- **ReDoc:** http://localhost:8000/redoc

---

## Paso 8 — Obtener un token JWT

Para usar los endpoints autenticados, necesitas un token JWT de operador. Genera uno desde Python:

```python
from pantheon.acme.feedback_auth import create_operator_token
import os

token = create_operator_token(
    operator_id="op_001",
    jwt_secret=os.environ["PANTHEON_JWT_SECRET"],
    expire_hours=8
)
print(token)
```

O desde la línea de comandos:

```bash
uv run python -c "
import os
from pantheon.acme.feedback_auth import create_operator_token
token = create_operator_token('op_001', os.environ['PANTHEON_JWT_SECRET'])
print(token)
"
```

Usa el token en las peticiones:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/hypotheses
```

---

## Paso 9 (opcional) — Descargar modelo de spaCy

El módulo Ornith usa spaCy para extracción de IOCs. Descarga el modelo en inglés:

```bash
uv run python -m spacy download en_core_web_sm
```

---

## Comandos de desarrollo frecuentes

```bash
# Instalar/actualizar dependencias
uv sync

# Correr todos los tests
uv run pytest

# Correr solo los tests adversariales
uv run pytest tests/adversarial/ -v

# Correr tests con reporte de cobertura
uv run pytest --cov=src/pantheon --cov-report=term-missing

# Reiniciar la infraestructura
docker compose down && docker compose up -d

# Ver logs de un servicio
docker compose logs -f qdrant
```

---

## Solución de problemas frecuentes

### "Connection refused" a PostgreSQL

```bash
# Verifica que el contenedor esté corriendo
docker compose ps

# Si no está corriendo, inícialo
docker compose up -d postgres
```

### "PANTHEON_JWT_SECRET not set"

El archivo `.env` no se cargó correctamente. Verifica que exista y que esté en el directorio raíz del proyecto.

### Tests de integración fallan con error de BD

Asegúrate de haber ejecutado `uv run python scripts/init_db.py` después de levantar Docker.

### Puerto 8000 ya en uso

```bash
uv run uvicorn pantheon.api.main:app --reload --port 8080
```

---
---

# Installation Instructions — Pantheon v2.1

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Python | 3.12 | https://python.org |
| uv | 0.4+ | `pip install uv` |
| Docker Desktop | 4.x | https://docker.com |
| Git | 2.x | https://git-scm.com |

> **Note:** Pantheon does not work on Python 3.11 or earlier. Use `python --version` to verify.

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/Gusmal02/pantheon.git
cd pantheon
```

---

## Step 2 — Configure environment variables

Copy the example file and edit it with your values:

```bash
cp .env.example .env
```

Open `.env` in your editor and configure at least these variables:

```env
# Required (the system will NOT start without them)
POSTGRES_PASSWORD=your_secure_password_here
PANTHEON_JWT_SECRET=a_random_string_of_at_least_32_characters
PANTHEON_ENCLAVE_KEY=another_random_string_of_at_least_32_characters

# Qdrant (if using remote instance, otherwise leave defaults)
QDRANT_HOST=localhost
QDRANT_PORT=6333

# Redis
REDIS_URL=redis://localhost:6379/0

# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=pantheon
POSTGRES_USER=pantheon

# Ares v3.2 integration (optional — only if using the Purple Bridge)
ARES_API_URL=http://localhost:8001
```

> **Important:** Never commit the `.env` file to Git. It's already in `.gitignore`.

To generate secure secret values:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Step 3 — Start infrastructure with Docker

Pantheon needs PostgreSQL, Redis, and Qdrant. Docker Compose starts them all:

```bash
docker compose up -d
```

Verify that containers are running:

```bash
docker compose ps
```

You should see three services in `running` state:
- `pantheon-postgres`
- `pantheon-redis`
- `pantheon-qdrant`

If any fails, check the logs:
```bash
docker compose logs postgres   # or redis, or qdrant
```

---

## Step 4 — Install Python dependencies

```bash
uv sync
```

This creates a virtual environment in `.venv/` and installs all dependencies from `pyproject.toml`. The first time may take 2-3 minutes.

---

## Step 5 — Initialize the database

```bash
uv run python scripts/init_db.py
```

This script creates the `audit_trail`, `episodes`, and `operators` tables in PostgreSQL. If the tables already exist, the script respects them (uses `CREATE TABLE IF NOT EXISTS`).

---

## Step 6 — Run tests (verification)

```bash
uv run pytest
```

Expected output:
```
341 passed in ~20s
```

If any test fails, verify:
1. That Docker containers are running (`docker compose ps`).
2. That environment variables are correctly configured.
3. That the DB schema was initialized (Step 5).

---

## Step 7 — Start the API

```bash
uv run uvicorn pantheon.api.main:app --reload --port 8000
```

The API will be available at:
- **Swagger UI:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/health
- **ReDoc:** http://localhost:8000/redoc

---

## Step 8 — Get a JWT token

To use authenticated endpoints, you need an operator JWT token. Generate one from Python:

```python
from pantheon.acme.feedback_auth import create_operator_token
import os

token = create_operator_token(
    operator_id="op_001",
    jwt_secret=os.environ["PANTHEON_JWT_SECRET"],
    expire_hours=8
)
print(token)
```

Or from the command line:

```bash
uv run python -c "
import os
from pantheon.acme.feedback_auth import create_operator_token
token = create_operator_token('op_001', os.environ['PANTHEON_JWT_SECRET'])
print(token)
"
```

Use the token in requests:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/hypotheses
```

---

## Step 9 (optional) — Download spaCy model

The Ornith module uses spaCy for IOC extraction. Download the English model:

```bash
uv run python -m spacy download en_core_web_sm
```

---

## Common Development Commands

```bash
# Install/update dependencies
uv sync

# Run all tests
uv run pytest

# Run only adversarial tests
uv run pytest tests/adversarial/ -v

# Run tests with coverage report
uv run pytest --cov=src/pantheon --cov-report=term-missing

# Restart infrastructure
docker compose down && docker compose up -d

# View service logs
docker compose logs -f qdrant
```

---

## Common Troubleshooting

### "Connection refused" to PostgreSQL

```bash
# Verify the container is running
docker compose ps

# If not running, start it
docker compose up -d postgres
```

### "PANTHEON_JWT_SECRET not set"

The `.env` file wasn't loaded correctly. Verify it exists and is in the project root directory.

### Integration tests fail with DB error

Make sure you ran `uv run python scripts/init_db.py` after starting Docker.

### Port 8000 already in use

```bash
uv run uvicorn pantheon.api.main:app --reload --port 8080
```

# Pantheon v2.1 — Reglas de integridad (no negociables)

## Reglas de seguridad estructurales

1. **Decisiones de autorización siempre deterministas.**
   - Validación de playbooks: allowlist SHA-256 + Pydantic.
   - Validación de IOCs/scope: regex + ipaddress + allowlist.
   - El LLM **nunca decide** — solo genera texto explicativo.

2. **Fail-closed en todos los gates.**
   - Timeout en ApprovalGate == denegado. Sin excepciones.
   - Circuit breaker del Input Guard: si se satura, modo contingencia (cuarentena), nunca bypass.
   - Timeout de Muralla == bloqueado.

3. **Chain hash obligatorio en Audit Trail.**
   - `chain_hash_n = SHA-256(action_n|timestamp_n|operator_id_n|nonce_n|chain_hash_{n-1})`
   - El primer registro usa `genesis_hash(session_id)`.
   - Nunca romper la cadena — el patrón Outbox garantiza atomicidad.

4. **Pre-commit log con fsync antes de retornar.**
   - `PreCommitLog.write()` llama `os.fsync()` antes de devolver el control.
   - El worker de Outbox NO marca `replicated=TRUE` hasta confirmar el fsync.

5. **Patrón Transactional Outbox para Audit Trail.**
   - Escritura primaria: `INSERT INTO audit_trail (..., replicated=FALSE)` dentro de la misma transacción ACID que la operación que la genera.
   - Worker independiente: lee `replicated=FALSE`, genera pre-commit log + WORM, marca `replicated=TRUE`.
   - Nunca escribir directamente al precommit.log desde el path de negocio.

6. **Sin credenciales hardcoded.**
   - Todo por variables de entorno (ver `.env.example`).
   - `PANTHEON_JWT_SECRET`, `PANTHEON_ENCLAVE_KEY`, `POSTGRES_PASSWORD` — siempre desde env.

7. **JWT con firma obligatoria para feedback de operador.**
   - El War Room firma cada payload de feedback con HMAC derivado del JWT.
   - El backend verifica la firma antes de incorporar el feedback al modelo IPCA.
   - `operator_id` viaja dentro del token, nunca en el cuerpo del request sin firma.

8. **Sin reescribir archivos completos si el cambio es < 20 líneas.**
   - Usar `Edit` (diff parcial) en lugar de `Write` (sobreescritura completa).

## Stack

Python 3.12 + uv · FastAPI · LangGraph · PostgreSQL (asyncpg) · Redis Streams · Qdrant · Gradio · spaCy · LightGBM · scikit-learn · Pydantic · NetworkX · Docker Compose · pytest

## Comandos de desarrollo

```bash
# Instalar dependencias
uv sync

# Correr tests
uv run pytest

# Inicializar schema de BD
uv run python scripts/init_db.py

# Levantar infraestructura
docker compose up -d
```

## Variables de entorno requeridas

Ver `.env.example` para la lista completa. Las críticas:
- `PANTHEON_JWT_SECRET` — firma de tokens JWT de operador
- `PANTHEON_ENCLAVE_KEY` — firma HMAC del pre-commit log
- `POSTGRES_PASSWORD` — contraseña de PostgreSQL
- `QDRANT_HOST` — host de Qdrant (default: localhost)

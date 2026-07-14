# Documentación Técnica — Pantheon v2.1

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| Lenguaje | Python 3.12 |
| Gestión de dependencias | `uv` |
| API REST | FastAPI + Uvicorn |
| Base de datos | PostgreSQL 16 (asyncpg) |
| Mensajería | Redis Streams |
| Búsqueda vectorial | Qdrant + FastEmbed |
| NER de IOCs | spaCy |
| ML clásico | scikit-learn (IsolationForest, IncrementalPCA), LightGBM, HDBSCAN |
| Agente LLM | LangGraph + LangChain Core |
| UI de operador | Gradio |
| Grafos | NetworkX |
| Validación de datos | Pydantic v2 |
| Métricas | prometheus-client |
| Testing | pytest + pytest-asyncio + pytest-cov |
| Contenedores | Docker Compose |

---

## Módulos principales

### 1. Centinela — Detección de anomalías

**Archivo:** `src/pantheon/centinela/`

Centinela usa un modelo de `IsolationForest` de scikit-learn para detectar vectores de características anómalos en el tráfico de red. La puntuación de anomalía se combina con la distancia al centroide del clúster (HDBSCAN) y la similaridad temporal (coseno sobre ventana deslizante de 1 hora) para producir el **Índice de Confianza Compuesto (CCI)**:

```
CCI = 0.50 × P_anomaly + 0.30 × (1 − D_centroid_norm) + 0.20 × C_temp
```

- `CCI < 0.45` → `LOW_CONFIDENCE`
- `0.45 ≤ CCI < 0.75` → `MODERATE`
- `CCI ≥ 0.75` → `CRITICAL`

La puntuación de anomalía se calcula como `1.0 − clip(raw_score + 0.5, 0, 1)`, donde `raw_score` es la `decision_function` del IsolationForest.

### 2. Ornith — Memoria episódica

**Archivo:** `src/pantheon/ornith/`

Ornith almacena episodios de incidentes pasados en Qdrant usando embeddings densos (fastembed) y dispersos (BM25). La búsqueda híbrida combina ambas modalidades con fusión de ranking reciproco (RRF). Antes de indexar, un pipeline de spaCy extrae IOCs (IPs, dominios, hashes, CVEs) del texto mediante reconocimiento de entidades nombradas (NER) personalizado.

**Schema del episodio:** `src/pantheon/ornith/episode_schema.py`
- `episode_id`, `timestamp`, `ttp_tags`, `severity`, `ioc_list`, `narrative`, `resolution`, `embedding_dense`, `embedding_sparse`

### 3. Acme Ranker — Ranking de hipótesis

**Archivo:** `src/pantheon/acme/`

Pipeline de dos etapas:

**Stage 1 (LightGBM):** Ranker contextual entrenado con características globales:
- `urgency_score`, `novelty_score`, `ttp_coverage`, `playbook_success_rate`, `timestamp_score`

**Stage 2 (IPCA por analista):** Cada operador tiene un perfil `IncrementalPCA` que captura su estilo de evaluación. El score final se combina:

```
final = 0.6 × stage1_score + 0.4 × ipca_score
```

El Stage 2 solo se activa tras 5 muestras de feedback (calibración mínima). Si el feedback se desvía más de 3σ del historial del operador, se lanza `OutlierFeedback` y el update se bloquea hasta que el operador confirme explícitamente.

### 4. Muralla — Validación de playbooks

**Archivo:** `src/pantheon/muralla/`

Guard determinista de tres pasos (el LLM no interviene):

1. **Allowlist SHA-256:** el hash del playbook debe estar en `policy/curated_playbooks.json`.
2. **Validación Pydantic:** los parámetros del playbook se validan contra el modelo correspondiente (`IsolateHostParams`, `BlockIpParams`, etc.).
3. **Verificación de scope:** la IP target debe estar en una red permitida (`policy/sim_scope.json`) y no ser una IP excluida. La acción debe estar en `allowed_playbook_actions`.

Cualquier falla en cualquier paso → `ValidationResult.REJECTED`.

### 5. Guards — Filtro de entrada

**Archivo:** `src/pantheon/guards/`

**Clasificador de logs** (`classifier.py`): regex para detectar intentos de inyección de prompt (patrones `[INST]`, `<system>`, `DAN`, `OVERRIDE SAFETY`, etc.) y patrones ambiguos.

**Circuit Breaker** (`circuit_breaker.py`): control de tasa con tres estados:
- `CLOSED` → normal
- `OPEN` → tasa excedida, bloqueo activo
- `HALF` → cooldown transcurrido, período de prueba

Transiciones: `OPEN→HALF` requiere solo tiempo (no cero eventos); `HALF→CLOSED` requiere tiempo + cero eventos en ventana; `HALF→OPEN` si llega nuevo exceso.

**InputGuard** (`guard.py`): combina clasificador + circuit breaker. Eventos en cuarentena se acumulan en buffer con callback opcional.

### 6. Audit Trail — Registro criptográfico

**Archivo:** `src/pantheon/audit/`

Implementa el **patrón Transactional Outbox** en dos capas:

**Capa primaria (PostgreSQL):**
- `INSERT INTO audit_trail (..., replicated=FALSE)` dentro de la misma transacción ACID que la operación de negocio.
- Garantiza atomicidad: el evento se registra o la operación no se ejecuta.

**Worker de Outbox** (`worker.py`):
- Lee registros con `replicated=FALSE` en lotes de 50.
- Para cada registro: escribe al pre-commit log con `fsync` → replica a WORM → marca `replicated=TRUE`.
- `WORMError` → reintento en el siguiente ciclo (sin marcar `replicated=TRUE`).

**Pre-commit Log** (`enclave.py`):
- Cada línea: JSON con `chain_hash`, `hmac_sig`, `nonce`, `timestamp`, `operator_id`.
- `chain_hash_n = SHA-256(action|timestamp|operator_id|nonce|chain_hash_{n-1})`
- Semilla: `genesis_hash(session_id) = SHA-256("genesis:{session_id}")`
- `os.fsync()` obligatorio antes de retornar el control al worker.
- `verify_chain()` reconstruye la cadena y valida cada HMAC.

### 7. API REST

**Archivo:** `src/pantheon/api/main.py`

FastAPI con autenticación Bearer JWT en todos los endpoints excepto `/health`.

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/health` | Estado del servicio |
| `POST` | `/events` | Ingestar evento de red |
| `GET` | `/hypotheses` | Hipótesis rankeadas |
| `POST` | `/approve/{id}` | Aprobar contención |
| `POST` | `/deny/{id}` | Denegar contención |
| `GET` | `/pending` | Solicitudes pendientes |
| `POST` | `/feedback` | Feedback dimensional firmado |
| `GET` | `/audit` | Últimas N entradas del audit trail |
| `POST` | `/killswitch` | Activar kill switch |

**Seguridad JWT:** tokens HS256 con `exp`, `sub` (operator_id) y `scope`. El `decode_operator_token` verifica firma antes de decodificar payload (previene ataque `alg:none`).

### 8. Caché Semántico

**Archivo:** `src/pantheon/cache/semantic.py`

Evita invocaciones redundantes al LLM para anomalías similares. El fingerprint del contexto:

```
fingerprint = SHA-256(normalized_vec_bytes ‖ sorted_doc_ids_json ‖ template_hash)
```

El vector se normaliza (L2) y se redondea a 4 decimales antes de serializar a bytes. Los `doc_ids` se ordenan para invariancia de orden. Backend: Redis con TTL configurable (fallback a dict en memoria para tests).

### 9. Grafo ATT&CK

**Archivo:** `src/pantheon/attck_graph/graph.py`

NetworkX DiGraph con 14 aristas por defecto mapeando las relaciones entre técnicas MITRE ATT&CK (T1595→T1190→T1059, etc.). `expand_hypothesis()` calcula la frecuencia de sucesores a profundidad 2 para enriquecer hipótesis con TTPs relacionadas.

---

## Seguridad — Principios no negociables

1. **Decisiones deterministas:** la allowlist, Pydantic y los parsers de ipaddress toman las decisiones de autorización. El LLM solo genera texto explicativo.
2. **Fail-closed:** timeout en cualquier gate == denegado. Circuit breaker saturado → cuarentena, nunca bypass.
3. **Chain hash:** integridad criptográfica de cada registro del audit trail.
4. **fsync obligatorio:** el pre-commit log garantiza escritura a disco antes de retornar.
5. **Sin credenciales hardcoded:** todo via variables de entorno.
6. **JWT firmado para feedback:** `key = SHA-256(jwt_secret:operator_id)` — previene envenenamiento cross-operador.
7. **Detección de outliers en IPCA:** feedback que se desvía >3σ requiere confirmación explícita.

---

## Tests

```
221 tests  |  0 fallos  |  ~9s
```

| Suite | Cobertura |
|---|---|
| `tests/unit/` | Todos los módulos (200 tests) |
| `tests/adversarial/` | 6 vectores de ataque (21 tests) |

Vectores adversariales cubiertos:
- Prompt injection en logs de red
- Suplantación de identidad en feedback (firma forjada, replay cross-operador, tamper post-firma)
- Envenenamiento del perfil IPCA
- Bypass de Muralla (hash desconocido, IP externa, overflow de duración, inyección en parámetros)
- Tampering de chain hash y HMAC en el pre-commit log
- Ataques JWT (expirado, secreto incorrecto, payload alterado, `alg:none`)

---
---

# Technical Documentation — Pantheon v2.1

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Dependency management | `uv` |
| REST API | FastAPI + Uvicorn |
| Database | PostgreSQL 16 (asyncpg) |
| Messaging | Redis Streams |
| Vector search | Qdrant + FastEmbed |
| IOC NER | spaCy |
| Classical ML | scikit-learn (IsolationForest, IncrementalPCA), LightGBM, HDBSCAN |
| LLM agent | LangGraph + LangChain Core |
| Operator UI | Gradio |
| Graphs | NetworkX |
| Data validation | Pydantic v2 |
| Metrics | prometheus-client |
| Testing | pytest + pytest-asyncio + pytest-cov |
| Containers | Docker Compose |

---

## Core Modules

### 1. Centinela — Anomaly Detection

**File:** `src/pantheon/centinela/`

Centinela uses a scikit-learn `IsolationForest` to detect anomalous feature vectors in network traffic. The anomaly score is combined with cluster centroid distance (HDBSCAN) and temporal similarity (cosine over a 1-hour sliding window) to produce the **Composite Confidence Index (CCI)**:

```
CCI = 0.50 × P_anomaly + 0.30 × (1 − D_centroid_norm) + 0.20 × C_temp
```

- `CCI < 0.45` → `LOW_CONFIDENCE`
- `0.45 ≤ CCI < 0.75` → `MODERATE`
- `CCI ≥ 0.75` → `CRITICAL`

The anomaly score is computed as `1.0 − clip(raw_score + 0.5, 0, 1)`, where `raw_score` is the IsolationForest `decision_function`.

### 2. Ornith — Episodic Memory

**File:** `src/pantheon/ornith/`

Ornith stores past incident episodes in Qdrant using both dense (fastembed) and sparse (BM25) embeddings. Hybrid search combines both modalities with Reciprocal Rank Fusion (RRF). Before indexing, a spaCy pipeline extracts IOCs (IPs, domains, hashes, CVEs) via custom Named Entity Recognition (NER).

**Episode schema:** `src/pantheon/ornith/episode_schema.py`
- `episode_id`, `timestamp`, `ttp_tags`, `severity`, `ioc_list`, `narrative`, `resolution`, `embedding_dense`, `embedding_sparse`

### 3. Acme Ranker — Hypothesis Ranking

**File:** `src/pantheon/acme/`

Two-stage pipeline:

**Stage 1 (LightGBM):** Contextual ranker trained on global features:
- `urgency_score`, `novelty_score`, `ttp_coverage`, `playbook_success_rate`, `timestamp_score`

**Stage 2 (per-analyst IPCA):** Each operator has an `IncrementalPCA` profile capturing their evaluation style. Final score:

```
final = 0.6 × stage1_score + 0.4 × ipca_score
```

Stage 2 activates only after 5 feedback samples (minimum calibration). If feedback deviates more than 3σ from the operator's history, `OutlierFeedback` is raised and the update is blocked until explicitly confirmed.

### 4. Muralla — Playbook Validation

**File:** `src/pantheon/muralla/`

Deterministic three-gate guard (LLM is not involved):

1. **SHA-256 allowlist:** the playbook hash must be registered in `policy/curated_playbooks.json`.
2. **Pydantic validation:** playbook parameters are validated against the corresponding model (`IsolateHostParams`, `BlockIpParams`, etc.).
3. **Scope verification:** the target IP must be in an allowed network (`policy/sim_scope.json`) and not be an excluded IP. The action must be in `allowed_playbook_actions`.

Any failure at any step → `ValidationResult.REJECTED`.

### 5. Guards — Input Filter

**File:** `src/pantheon/guards/`

**Log classifier** (`classifier.py`): regex to detect prompt injection attempts (patterns `[INST]`, `<system>`, `DAN`, `OVERRIDE SAFETY`, etc.) and ambiguous patterns.

**Circuit Breaker** (`circuit_breaker.py`): rate control with three states:
- `CLOSED` → normal
- `OPEN` → rate exceeded, active blocking
- `HALF` → cooldown elapsed, probe period

Transitions: `OPEN→HALF` requires only time elapsed (not zero events); `HALF→CLOSED` requires time + zero events in window; `HALF→OPEN` on new rate excess.

**InputGuard** (`guard.py`): combines classifier + circuit breaker. Quarantined events accumulate in a buffer with an optional callback.

### 6. Audit Trail — Cryptographic Log

**File:** `src/pantheon/audit/`

Implements the **Transactional Outbox pattern** in two layers:

**Primary layer (PostgreSQL):**
- `INSERT INTO audit_trail (..., replicated=FALSE)` inside the same ACID transaction as the business operation.
- Guarantees atomicity: the event is recorded or the operation doesn't execute.

**Outbox Worker** (`worker.py`):
- Reads records with `replicated=FALSE` in batches of 50.
- For each record: writes to pre-commit log with `fsync` → replicates to WORM → marks `replicated=TRUE`.
- `WORMError` → retry on next cycle (without marking `replicated=TRUE`).

**Pre-commit Log** (`enclave.py`):
- Each line: JSON with `chain_hash`, `hmac_sig`, `nonce`, `timestamp`, `operator_id`.
- `chain_hash_n = SHA-256(action|timestamp|operator_id|nonce|chain_hash_{n-1})`
- Seed: `genesis_hash(session_id) = SHA-256("genesis:{session_id}")`
- `os.fsync()` mandatory before returning control to the worker.
- `verify_chain()` reconstructs the chain and validates each HMAC.

### 7. REST API

**File:** `src/pantheon/api/main.py`

FastAPI with Bearer JWT authentication on all endpoints except `/health`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health |
| `POST` | `/events` | Ingest network event |
| `GET` | `/hypotheses` | Ranked hypotheses |
| `POST` | `/approve/{id}` | Approve containment |
| `POST` | `/deny/{id}` | Deny containment |
| `GET` | `/pending` | Pending requests |
| `POST` | `/feedback` | Signed dimensional feedback |
| `GET` | `/audit` | Last N audit trail entries |
| `POST` | `/killswitch` | Trigger kill switch |

**JWT security:** HS256 tokens with `exp`, `sub` (operator_id), and `scope`. `decode_operator_token` verifies the signature before decoding the payload (prevents `alg:none` attack).

### 8. Semantic Cache

**File:** `src/pantheon/cache/semantic.py`

Prevents redundant LLM calls for similar anomalies. Context fingerprint:

```
fingerprint = SHA-256(normalized_vec_bytes ‖ sorted_doc_ids_json ‖ template_hash)
```

The vector is L2-normalized and rounded to 4 decimal places before serializing to bytes. `doc_ids` are sorted for order invariance. Backend: Redis with configurable TTL (in-memory dict fallback for tests).

### 9. ATT&CK Graph

**File:** `src/pantheon/attck_graph/graph.py`

NetworkX DiGraph with 14 default edges mapping relationships between MITRE ATT&CK techniques (T1595→T1190→T1059, etc.). `expand_hypothesis()` computes successor frequency at depth 2 to enrich hypotheses with related TTPs.

---

## Security — Non-negotiable Principles

1. **Deterministic decisions:** the allowlist, Pydantic, and ipaddress parsers make authorization decisions. The LLM only generates explanatory text.
2. **Fail-closed:** timeout at any gate == denied. Saturated circuit breaker → quarantine, never bypass.
3. **Chain hash:** cryptographic integrity of every audit trail record.
4. **Mandatory fsync:** the pre-commit log guarantees disk write before returning.
5. **No hardcoded credentials:** everything via environment variables.
6. **Signed JWT for feedback:** `key = SHA-256(jwt_secret:operator_id)` — prevents cross-operator poisoning.
7. **IPCA outlier detection:** feedback deviating >3σ requires explicit confirmation.

---

## Tests

```
221 tests  |  0 failures  |  ~9s
```

| Suite | Coverage |
|---|---|
| `tests/unit/` | All modules (200 tests) |
| `tests/adversarial/` | 6 attack vectors (21 tests) |

Adversarial vectors covered:
- Prompt injection in network logs
- Identity impersonation in feedback (forged signature, cross-operator replay, post-signing tamper)
- IPCA profile poisoning
- Muralla bypass (unknown hash, external IP, duration overflow, parameter injection)
- Chain hash and HMAC tampering in the pre-commit log
- JWT attacks (expired, wrong secret, altered payload, `alg:none`)

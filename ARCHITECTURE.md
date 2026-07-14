# Arquitectura — Pantheon v2.1

## Visión general

Pantheon es un sistema de caza de amenazas compuesto por ocho subsistemas especializados que se comunican mediante eventos asíncronos (Redis Streams) y coordinan mediante una API REST central. El principio rector es la **separación de decisión y ejecución**: la IA sugiere, el humano y las reglas deterministas autorizan.

```
Red corporativa
      │
      ▼
┌─────────────┐    ┌─────────────┐
│  InputGuard │───▶│  Centinela  │
│  (Guards)   │    │  (anomaly)  │
└─────────────┘    └──────┬──────┘
                          │ CCI ≥ threshold
                          ▼
                   ┌──────────────┐    ┌────────────┐
                   │    Ornith    │───▶│ ATT&CK     │
                   │  (episodic  │    │  Graph     │
                   │   memory)   │    └────────────┘
                   └──────┬───────┘
                          │ docs + TTPs
                          ▼
                   ┌──────────────┐    ┌────────────┐
                   │ Acme Ranker  │◀───│   IPCA     │
                   │ (Stage1+2)  │    │ (per-op)   │
                   └──────┬───────┘    └────────────┘
                          │ hipótesis rankeadas
                          ▼
                   ┌──────────────┐
                   │  War Room   │  ◀── Operador humano
                   │  (Gradio)   │
                   └──────┬───────┘
                          │ playbook seleccionado
                          ▼
                   ┌──────────────┐
                   │   Muralla   │  ← política determinista
                   │  (3 gates)  │
                   └──────┬───────┘
                          │ ALLOWED
                          ▼
                   ┌──────────────┐
                   │ ApprovalGate │  ← aprobación humana
                   └──────┬───────┘
                          │
                          ▼
                   ┌──────────────┐    ┌─────────────────┐
                   │  Audit Trail │───▶│  PreCommitLog   │
                   │  (Outbox)   │    │  (WORM + fsync) │
                   └──────────────┘    └─────────────────┘
```

---

## Decisiones de arquitectura

### 1. Patrón Transactional Outbox para el Audit Trail

**Problema:** El registro de auditoría debe ser atómico con la operación de negocio. Si el sistema falla entre "operar" y "registrar", el audit trail quedaría incompleto y no sería confiable para auditorías forenses.

**Decisión:** Usar el patrón Transactional Outbox:
1. El `INSERT INTO audit_trail (replicated=FALSE)` ocurre en la **misma transacción ACID** que la operación de negocio. Si la operación falla, el registro tampoco se inserta.
2. Un worker independiente lee los registros `replicated=FALSE`, los escribe al pre-commit log con `fsync`, los replica al WORM, y marca `replicated=TRUE`.
3. El path de negocio **nunca escribe directamente al pre-commit log**.

**Alternativas descartadas:**
- Escritura directa al log: no atómica, puede haber registros sin operación o viceversa.
- Evento en Redis Streams: Redis no garantiza exactly-once delivery; el audit trail debe ser perfecto.

### 2. Chain hash + HMAC por línea

**Problema:** Un atacante con acceso al sistema de archivos podría modificar entradas del log sin dejar rastro.

**Decisión:** Cada línea incluye:
- `chain_hash_n = SHA-256(action|timestamp|operator_id|nonce|chain_hash_{n-1})` — vincula la línea a su predecesora.
- `hmac_sig = HMAC-SHA256(json_payload, enclave_key)` — prueba de autenticidad independiente.

Si alguien modifica cualquier campo, ambas verificaciones fallan. `verify_chain()` detecta la primera línea corrupta.

**Alternativas descartadas:**
- Solo hash sin HMAC: sin clave, cualquiera que conozca el algoritmo puede recalcular el hash.
- Merkle tree: más complejo, sin ventaja práctica para este caso de uso append-only.

### 3. Fail-closed en todos los gates

**Problema:** Los sistemas de seguridad bajo presión (alta carga, fallos de red, timeouts) tienden a degradarse "graciosamente" abriendo accesos. Esto crea ventanas de ataque.

**Decisión:** Todos los gates tienen semántica fail-closed:
- `ApprovalGate`: timeout → denegado. Sin excepción.
- `CircuitBreaker`: saturación → cuarentena. Nunca bypass.
- `MurallaGuard`: hash desconocido → REJECTED. Sin fallback.
- `PreCommitLog`: fallo de fsync → excepción propagada, operación revertida.

**Consecuencia aceptada:** mayor fricción operacional durante fallos. Es preferible a un incidente de seguridad.

### 4. LLM solo genera texto, nunca decide

**Problema:** Los modelos de lenguaje son impredecibles bajo prompt injection, alucinaciones y distributional shift. Usarlos para decisiones de autorización crea vulnerabilidades no deterministas.

**Decisión:** El LLM (Hermes/LangGraph) solo produce texto explicativo (hipótesis, narrativas). Las decisiones de autorización las toman:
- SHA-256 allowlist (Muralla)
- `ipaddress.ip_network()` + regex (scope)
- Pydantic validators (parámetros)
- `hmac.compare_digest()` (firmas)

**Consecuencia:** el sistema es auditable, determinista y resistente a prompt injection. La "inteligencia" está en la priorización, no en el control de acceso.

### 5. IPCA incremental por analista con detección de outliers

**Problema:** El feedback de un analista puede estar comprometido (credenciales robadas) o simplemente equivocado. Un modelo que acepta todo el feedback indiscriminadamente es vulnerable a envenenamiento.

**Decisión:** Dos defensas en capas:
1. **Firma HMAC obligatoria:** `key = SHA-256(jwt_secret:operator_id)`. Previene feedback de un operador en nombre de otro.
2. **Detección de outliers:** si el vector de feedback se desvía >3σ del historial reciente del operador, se lanza `OutlierFeedback` y el update requiere `force=True` explícito.

El `IncrementalPCA` se usa porque permite actualización online sin reentrenar desde cero; es eficiente en memoria para sesiones largas.

### 6. Circuit Breaker con transición OPEN→HALF solo por tiempo

**Problema:** El circuit breaker estándar (OPEN→HALF cuando `recent_events == 0`) puede bloquearse indefinidamente si el sistema sigue recibiendo eventos a ritmo bajo. Esto crearía una denegación de servicio auto-infligida.

**Decisión:** La transición `OPEN→HALF` requiere solo que haya transcurrido el tiempo de cooldown, independientemente de si siguen llegando eventos. `HALF→CLOSED` requiere tiempo + cero eventos (verifica que la carga se normalizó).

Este diseño permite recuperarse del estado OPEN incluso bajo carga moderada continua.

### 7. Búsqueda híbrida en Ornith (densa + dispersa)

**Problema:** La búsqueda solo por embeddings densos falla con IOCs exactos (hashes, IPs, nombres de dominios específicos). La búsqueda solo por BM25 falla con similitud semántica.

**Decisión:** Qdrant híbrido con fusión RRF (Reciprocal Rank Fusion):
- Embeddings densos (fastembed): similitud semántica de narrativas.
- Embeddings dispersos (BM25): coincidencia exacta de IOCs y términos técnicos.
- RRF combina los rankings sin necesidad de normalizar scores absolutos.

### 8. Caché semántico con fingerprint SHA-256

**Problema:** Múltiples eventos con la misma anomalía y el mismo contexto de documentos invocarían el LLM repetidamente, con alto costo y latencia.

**Decisión:** Fingerprint determinista que captura todo el contexto de entrada:
```
SHA-256(L2_normalized_vec_bytes ‖ sorted_doc_ids_json ‖ template_hash)
```

La normalización L2 y el redondeo a 4 decimales garantizan que vectores "equivalentes" (con pequeñas diferencias de punto flotante) produzcan el mismo fingerprint. La ordenación de `doc_ids` garantiza invariancia de orden.

---

## Flujo de datos principal

```
1. Evento de red (log text + feature vector)
   └─▶ InputGuard.process()
       ├─ BLOCK/QUARANTINE → registro en audit trail + fin
       └─ PASS
           └─▶ Centinela.process()
               ├─ LOW_CONFIDENCE → descartado (log)
               └─ MODERATE/CRITICAL
                   └─▶ SemanticCache.get()
                       ├─ HIT → RankerResult desde caché
                       └─ MISS
                           └─▶ Ornith.search() → top-k episodios
                               └─▶ ATTCKGraph.expand_hypothesis() → TTPs
                                   └─▶ AcmeRanker.rank() → hipótesis ordenadas
                                       └─▶ SemanticCache.put()
                                           └─▶ War Room (display)
                                               └─▶ Operador selecciona playbook
                                                   └─▶ MurallaGuard.validate()
                                                       └─▶ ALLOWED
                                                           └─▶ ApprovalGate.request()
                                                               └─▶ APPROVED
                                                                   └─▶ AuditTrail.record_event()
                                                                       └─▶ OutboxWorker → PreCommitLog → WORM
```

---

## Estructura de directorios

```
pantheon/
├── src/pantheon/
│   ├── acme/          # Ranking de hipótesis (LightGBM + IPCA)
│   │   ├── feedback_auth.py   # JWT + firma HMAC de feedback
│   │   ├── ipca.py            # IncrementalPCA por operador
│   │   ├── ranker.py          # Pipeline Stage1+2
│   │   └── stage1.py          # LightGBM ranker
│   ├── api/           # FastAPI REST
│   ├── attck_graph/   # Grafo MITRE ATT&CK (NetworkX)
│   ├── audit/         # Audit Trail + Outbox
│   │   ├── enclave.py         # Pre-commit log con chain hash
│   │   ├── trail.py           # AuditTrail (PostgreSQL)
│   │   ├── worker.py          # OutboxWorker
│   │   └── worm.py            # Replicación WORM
│   ├── cache/         # Caché semántico
│   ├── centinela/     # Detección de anomalías
│   │   ├── cci.py             # Composite Confidence Index
│   │   ├── detector.py        # IsolationForest wrapper
│   │   └── pipeline.py        # Pipeline completo
│   ├── core/          # Config, ApprovalGate, EventBus
│   ├── guards/        # InputGuard, CircuitBreaker, Classifier
│   ├── hermes/        # Agente LangGraph (en construcción)
│   ├── muralla/       # Validación determinista de playbooks
│   │   ├── allowlist.py       # SHA-256 allowlist
│   │   └── validator.py       # MurallaGuard + SimScope
│   ├── ornith/        # Memoria episódica (Qdrant)
│   └── war_room/      # UI Gradio (en construcción)
├── policy/
│   ├── curated_playbooks.json # Allowlist de playbooks (SHA-256)
│   └── sim_scope.json         # Scope del entorno simulado
├── scripts/
│   └── init_db.py     # Schema PostgreSQL
├── tests/
│   ├── unit/          # Tests por módulo (200 tests)
│   └── adversarial/   # Tests de ataques (21 tests)
├── audit/             # Directorio del pre-commit log (runtime)
├── docker-compose.yml
├── pyproject.toml
└── .env.example
```

---
---

# Architecture — Pantheon v2.1

## Overview

Pantheon is a threat hunting system composed of eight specialized subsystems that communicate via asynchronous events (Redis Streams) and coordinate through a central REST API. The guiding principle is **separation of suggestion and authorization**: AI suggests, humans and deterministic rules authorize.

*(See the diagram above — it applies to both languages)*

---

## Architecture Decisions

### 1. Transactional Outbox Pattern for Audit Trail

**Problem:** The audit log must be atomic with the business operation. If the system fails between "operate" and "record," the audit trail would be incomplete and unreliable for forensic audits.

**Decision:** Use the Transactional Outbox pattern:
1. `INSERT INTO audit_trail (replicated=FALSE)` occurs in the **same ACID transaction** as the business operation. If the operation fails, the record is not inserted either.
2. An independent worker reads `replicated=FALSE` records, writes them to the pre-commit log with `fsync`, replicates to WORM, and marks `replicated=TRUE`.
3. The business path **never writes directly to the pre-commit log**.

**Discarded alternatives:**
- Direct log write: not atomic; records without operations or vice versa are possible.
- Redis Streams event: Redis does not guarantee exactly-once delivery; the audit trail must be perfect.

### 2. Chain Hash + Per-line HMAC

**Problem:** An attacker with filesystem access could modify log entries without leaving a trace.

**Decision:** Each line includes:
- `chain_hash_n = SHA-256(action|timestamp|operator_id|nonce|chain_hash_{n-1})` — links the line to its predecessor.
- `hmac_sig = HMAC-SHA256(json_payload, enclave_key)` — independent authenticity proof.

If anyone modifies any field, both verifications fail. `verify_chain()` detects the first corrupted line.

**Discarded alternatives:**
- Hash only without HMAC: without a key, anyone who knows the algorithm can recalculate the hash.
- Merkle tree: more complex, no practical advantage for this append-only use case.

### 3. Fail-Closed at All Gates

**Problem:** Security systems under pressure (high load, network failures, timeouts) tend to "gracefully" degrade by opening access. This creates attack windows.

**Decision:** All gates have fail-closed semantics:
- `ApprovalGate`: timeout → denied. No exception.
- `CircuitBreaker`: saturation → quarantine. Never bypass.
- `MurallaGuard`: unknown hash → REJECTED. No fallback.
- `PreCommitLog`: fsync failure → propagated exception, operation rolled back.

**Accepted consequence:** greater operational friction during failures. Preferable to a security incident.

### 4. LLM Generates Text Only, Never Decides

**Problem:** Language models are unpredictable under prompt injection, hallucinations, and distributional shift. Using them for authorization decisions creates non-deterministic vulnerabilities.

**Decision:** The LLM (Hermes/LangGraph) only produces explanatory text (hypotheses, narratives). Authorization decisions are made by:
- SHA-256 allowlist (Muralla)
- `ipaddress.ip_network()` + regex (scope)
- Pydantic validators (parameters)
- `hmac.compare_digest()` (signatures)

**Consequence:** the system is auditable, deterministic, and resistant to prompt injection. "Intelligence" is in prioritization, not in access control.

### 5. Per-Analyst Incremental PCA with Outlier Detection

**Problem:** An analyst's feedback might be compromised (stolen credentials) or simply wrong. A model that accepts all feedback indiscriminately is vulnerable to poisoning.

**Decision:** Two layered defenses:
1. **Mandatory HMAC signature:** `key = SHA-256(jwt_secret:operator_id)`. Prevents feedback from one operator being attributed to another.
2. **Outlier detection:** if the feedback vector deviates >3σ from the operator's recent history, `OutlierFeedback` is raised and the update requires explicit `force=True`.

`IncrementalPCA` is used because it allows online updates without retraining from scratch; memory-efficient for long sessions.

### 6. Circuit Breaker with OPEN→HALF Transition on Time Only

**Problem:** The standard circuit breaker (OPEN→HALF when `recent_events == 0`) can block indefinitely if the system keeps receiving events at a low rate. This creates a self-inflicted denial of service.

**Decision:** The `OPEN→HALF` transition requires only that the cooldown time has elapsed, regardless of whether events keep arriving. `HALF→CLOSED` requires time + zero events (verifies that load normalized).

This design allows recovery from OPEN state even under moderate continuous load.

### 7. Hybrid Search in Ornith (Dense + Sparse)

**Problem:** Dense-only embedding search fails with exact IOCs (hashes, IPs, specific domain names). BM25-only search fails with semantic similarity.

**Decision:** Hybrid Qdrant with Reciprocal Rank Fusion (RRF):
- Dense embeddings (fastembed): semantic similarity of narratives.
- Sparse embeddings (BM25): exact matching of IOCs and technical terms.
- RRF combines rankings without needing to normalize absolute scores.

### 8. Semantic Cache with SHA-256 Fingerprint

**Problem:** Multiple events with the same anomaly and document context would invoke the LLM repeatedly, with high cost and latency.

**Decision:** Deterministic fingerprint capturing all input context:
```
SHA-256(L2_normalized_vec_bytes ‖ sorted_doc_ids_json ‖ template_hash)
```

L2 normalization and rounding to 4 decimal places ensure that "equivalent" vectors (with small floating-point differences) produce the same fingerprint. `doc_ids` sorting ensures order invariance.

---

## Main Data Flow

*(See the Spanish section — the flow diagram applies to both languages)*

---

## Directory Structure

*(See the Spanish section — the structure diagram applies to both languages)*

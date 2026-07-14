"""
Purple Team Bridge — integración bidireccional Pantheon ↔ Ares v3.2.

FLUJO COMPLETO:
  1. Ares escanea la red → Acheron detecta comportamiento evasivo (icc < 0.55)
  2. MissionRunner escribe a purple_escalated (PostgreSQL de Ares)
  3. AresBridgeWorker de Pantheon hace polling a:
       GET {ARES_API_URL}/purple/escalated?since=<último poll ISO>
  4. Cada registro se convierte a vector de anomalía vía ares_finding_to_anomaly()
  5. El vector alimenta Centinela (IsolationForest); si CCI > 0.75 → contención
  6. Contención detectada → Pantheon publica en ares:killswitch
       {"reason": "ioc_detected", "source": "pantheon", "target": "<ip>"}
  7. Ares recibe el kill switch y aborta el engagement automáticamente.

MODO WEBHOOK (alternativo):
  POST /purple/escalated — Ares empuja directamente a Pantheon

Seguridad:
  - El payload de escalado se valida con Pydantic antes de procesarse.
  - La fuente del escalado (ares_source) se valida contra una allowlist de hosts.
  - El LLM nunca interviene en la validación.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel, field_validator

from pantheon.core.config import settings

logger = logging.getLogger(__name__)

# Allowlist de hosts Ares autorizados a publicar escalados
_ALLOWED_ARES_HOSTS = {
    "localhost",
    "127.0.0.1",
    "ares-api",           # nombre de servicio Docker
    "ares.internal",      # nombre interno de red
}

# Patrón de hypothesis_id: alfanumérico + guiones, máx 64 chars
_HYPOTHESIS_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,64}$")

# Almacén en memoria (siempre activo como fallback)
_escalated_store: list[dict] = []

# ── Persistencia en PostgreSQL ────────────────────────────────────────────────

def _db_connect():
    import psycopg2
    return psycopg2.connect(
        host=settings.postgres_host, port=settings.postgres_port,
        dbname=settings.postgres_db, user=settings.postgres_user,
        password=settings.postgres_password, connect_timeout=2,
    )


def _db_available() -> bool:
    try:
        conn = _db_connect()
        conn.close()
        return True
    except Exception:
        return False


# Estado de disponibilidad (evaluado una vez al importar para evitar latencia)
_USE_DB: bool = False

def _init_db_flag() -> None:
    global _USE_DB
    _USE_DB = _db_available()
    if _USE_DB:
        logger.info("purple_bridge: usando PostgreSQL como almacén primario")
    else:
        logger.info("purple_bridge: usando almacén en memoria (PostgreSQL no disponible)")

_init_db_flag()


# ── Modelos Pydantic ──────────────────────────────────────────────────────────

class EscalatedHypothesis(BaseModel):
    """Payload de un escalado recibido desde Ares v3.2."""

    hypothesis_id: str
    source_ip: str
    ttp_tags: list[str] = []
    severity: str = "moderate"
    narrative: str
    ares_source: str        # host de Ares que publica el escalado
    timestamp: float = field(default_factory=time.time)

    @field_validator("hypothesis_id")
    @classmethod
    def validate_hypothesis_id(cls, v: str) -> str:
        if not _HYPOTHESIS_ID_RE.match(v):
            raise ValueError(f"hypothesis_id inválido: {v!r}")
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"source_ip inválida: {v!r}") from exc
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "moderate", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity debe ser uno de {allowed}, got {v!r}")
        return v.lower()

    @field_validator("ares_source")
    @classmethod
    def validate_ares_source(cls, v: str) -> str:
        host = v.split(":")[0].strip()   # eliminar puerto si viene con host:port
        if host not in _ALLOWED_ARES_HOSTS:
            raise ValueError(f"ares_source no autorizado: {v!r}")
        return v

    @field_validator("narrative")
    @classmethod
    def validate_narrative(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("narrative no puede estar vacío")
        if len(v) > 2000:
            raise ValueError("narrative demasiado largo (máx 2000 chars)")
        return v.strip()


@dataclass
class EscalatedRecord:
    """Registro interno de un escalado procesado."""
    hypothesis: EscalatedHypothesis
    received_at: float = field(default_factory=time.time)
    content_hash: str = ""
    processed: bool = False

    def __post_init__(self):
        if not self.content_hash:
            raw = f"{self.hypothesis.hypothesis_id}:{self.hypothesis.source_ip}:{self.hypothesis.narrative}"
            self.content_hash = hashlib.sha256(raw.encode()).hexdigest()


# ── Lógica del bridge ─────────────────────────────────────────────────────────

class PurpleBridgeError(ValueError):
    """Error de validación en el Purple Bridge."""


def receive_escalated(payload: dict) -> EscalatedRecord:
    """
    Recibe y valida un escalado de Ares.

    Valida con Pydantic antes de almacenar. Rechaza duplicados por content_hash.
    Escribe en PostgreSQL si está disponible; siempre escribe en memoria.

    Raises:
        PurpleBridgeError si la validación falla o es duplicado.
    """
    try:
        hypothesis = EscalatedHypothesis(**payload)
    except Exception as exc:
        raise PurpleBridgeError(f"Payload de escalado inválido: {exc}") from exc

    record = EscalatedRecord(hypothesis=hypothesis)

    row = {
        "hypothesis_id": hypothesis.hypothesis_id,
        "source_ip":     hypothesis.source_ip,
        "ttp_tags":      hypothesis.ttp_tags,
        "severity":      hypothesis.severity,
        "narrative":     hypothesis.narrative,
        "ares_source":   hypothesis.ares_source,
        "timestamp":     hypothesis.timestamp,
        "received_at":   record.received_at,
        "content_hash":  record.content_hash,
        "processed":     False,
    }

    if _USE_DB:
        _db_receive(row, record.content_hash)
    else:
        # Evitar duplicados en memoria
        existing_hashes = {r["content_hash"] for r in _escalated_store}
        if record.content_hash in existing_hashes:
            raise PurpleBridgeError(f"Escalado duplicado detectado: {record.content_hash[:16]}…")
        _escalated_store.append(row)

    from pantheon.core.metrics import PURPLE_ESCALATED_TOTAL
    PURPLE_ESCALATED_TOTAL.inc()
    return record


def _db_receive(row: dict, content_hash: str) -> None:
    """INSERT en purple_escalated; lanza PurpleBridgeError si es duplicado."""
    try:
        import psycopg2
        conn = _db_connect()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO purple_escalated
                        (content_hash, hypothesis_id, source_ip, ttp_tags,
                         severity, narrative, ares_source, timestamp_ts, received_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        content_hash,
                        row["hypothesis_id"], row["source_ip"],
                        row["ttp_tags"],      row["severity"],
                        row["narrative"],     row["ares_source"],
                        row["timestamp"],     row["received_at"],
                    ),
                )
        conn.close()
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            raise PurpleBridgeError(f"Escalado duplicado detectado: {content_hash[:16]}…") from exc
        logger.warning("purple_bridge._db_receive: %s — usando fallback en memoria", exc)
        existing_hashes = {r["content_hash"] for r in _escalated_store}
        if content_hash in existing_hashes:
            raise PurpleBridgeError(f"Escalado duplicado detectado: {content_hash[:16]}…")
        _escalated_store.append(row)


def get_escalated(limit: int = 50, only_unprocessed: bool = False) -> list[dict]:
    """
    Devuelve los escalados recibidos desde Ares.

    Lee de PostgreSQL si está disponible, de lo contrario del almacén en memoria.
    """
    if _USE_DB:
        return _db_get_escalated(limit, only_unprocessed)

    results = _escalated_store
    if only_unprocessed:
        results = [r for r in results if not r["processed"]]
    return results[-limit:]


def _db_get_escalated(limit: int, only_unprocessed: bool) -> list[dict]:
    try:
        conn = _db_connect()
        where = "WHERE processed = FALSE" if only_unprocessed else ""
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT content_hash, hypothesis_id, source_ip, ttp_tags,
                       severity, narrative, ares_source, timestamp_ts, received_at, processed
                FROM purple_escalated
                {where}
                ORDER BY received_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        conn.close()
        return [
            {
                "content_hash":  r[0], "hypothesis_id": r[1],
                "source_ip":     r[2], "ttp_tags":      list(r[3]),
                "severity":      r[4], "narrative":     r[5],
                "ares_source":   r[6], "timestamp":     r[7],
                "received_at":   r[8], "processed":     r[9],
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning("purple_bridge._db_get_escalated: %s", exc)
        return []


def mark_processed(content_hash: str) -> bool:
    """Marca un escalado como procesado por Hermes."""
    if _USE_DB:
        return _db_mark_processed(content_hash)
    for record in _escalated_store:
        if record["content_hash"] == content_hash:
            record["processed"] = True
            return True
    return False


def _db_mark_processed(content_hash: str) -> bool:
    try:
        conn = _db_connect()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE purple_escalated SET processed = TRUE WHERE content_hash = %s",
                    (content_hash,),
                )
                updated = cur.rowcount
        conn.close()
        return updated > 0
    except Exception as exc:
        logger.warning("purple_bridge._db_mark_processed: %s", exc)
        return False


def clear_store() -> None:
    """Limpia el store. En tests: borra la memoria. Con DB: también trunca la tabla."""
    _escalated_store.clear()
    if _USE_DB:
        try:
            conn = _db_connect()
            with conn:
                with conn.cursor() as cur:
                    cur.execute("TRUNCATE TABLE purple_escalated")
            conn.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# LADO ACTIVO: Pantheon → polling Ares + Kill Switch cruzado
# ═══════════════════════════════════════════════════════════════════════════════

import json
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import numpy as np

# Callback opcional para que el AresBridgeWorker notifique a Centinela
CentinelaFeedFn = Callable[[str, np.ndarray], None]   # (source_ip, features)


# ── Conversión Ares record → vector de anomalía para Centinela ────────────────

def ares_finding_to_anomaly(record: dict) -> np.ndarray:
    """
    Convierte un registro purple_escalated de Ares en un vector de 8 features
    compatible con el IsolationForest de Centinela.

    Mapeo (idéntico al feature space de Acheron Stage 1 adaptado a Centinela):
      [0] 1 - icc          → señal de anomalía invertida (mayor = más sospechoso)
      [1] adversarial      → 1.0 si Isolation Forest de Ares lo marcó como evasivo
      [2] open_ports_norm  → conteo de puertos abiertos / 100
      [3] high_risk_norm   → conteo de findings high-severity / 50
      [4] service_norm     → total findings / 100
      [5] has_critical     → 1.0 si algún finding es "critical"
      [6] high_ports_norm  → puertos > 1024 abiertos / 50 (servicios no estándar)
      [7] icc_raw          → ICC original (referencia absoluta para Centinela)

    Args:
        record — dict de purple_escalated: {icc, adversarial, findings, target, ...}

    Returns:
        np.ndarray shape (8,) dtype float32
    """
    icc = float(record.get("icc", 0.5))
    adversarial = float(bool(record.get("adversarial", False)))
    findings = record.get("findings", [])

    open_ports = [
        f.get("port", 0) for f in findings
        if f.get("state") == "open" and f.get("port") is not None
    ]
    high_risk = [f for f in findings if f.get("severity") == "high"]
    critical  = [f for f in findings if f.get("severity") == "critical"]
    high_ports = [p for p in open_ports if p > 1024]

    return np.array([
        float(np.clip(1.0 - icc, 0.0, 1.0)),          # [0] inverted ICC
        adversarial,                                     # [1] evasive flag
        min(len(open_ports), 100) / 100.0,              # [2] open ports
        min(len(high_risk), 50) / 50.0,                 # [3] high risk
        min(len(findings), 100) / 100.0,                # [4] service count
        float(len(critical) > 0),                       # [5] has critical
        min(len(high_ports), 50) / 50.0,                # [6] non-standard ports
        float(np.clip(icc, 0.0, 1.0)),                  # [7] raw ICC
    ], dtype=np.float32)


# ── Kill Switch cruzado Pantheon → Ares ──────────────────────────────────────

def publish_killswitch_to_ares(
    redis_client: Any,
    reason: str,
    target_ip: str,
    operator_id: str = "pantheon",
) -> None:
    """
    Publica en el canal Redis de Kill Switch de Ares para abortar el engagement.

    Ares ya escucha 'ares:killswitch' — no requiere ningún cambio en Ares.

    Args:
        redis_client — cliente Redis (redis-py)
        reason       — motivo del kill switch ("ioc_detected", "cci_critical", etc.)
        target_ip    — IP que desencadenó la acción
        operator_id  — quién dispara (por defecto "pantheon" para acciones automáticas)

    Raises:
        RuntimeError si la publicación falla (para que el caller decida reintentar)
    """
    payload = json.dumps({
        "reason":      reason,
        "source":      "pantheon",
        "operator_id": operator_id,
        "target":      target_ip,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    })
    try:
        redis_client.publish("ares:killswitch", payload)
    except Exception as exc:
        raise RuntimeError(f"No se pudo publicar en ares:killswitch: {exc}") from exc


# ── Worker de polling activo ──────────────────────────────────────────────────

class AresBridgeWorker:
    """
    Worker que hace polling periódico al endpoint /purple/escalated de Ares.

    Por cada registro recibido:
      1. Convierte el record a vector de anomalía con ares_finding_to_anomaly().
      2. Llama al callback centinela_feed (si está configurado).
      3. Registra el record en el store local de Pantheon.

    Si CCI > cci_critical_threshold tras la evaluación de Centinela, el caller
    debe invocar publish_killswitch_to_ares() para abortar el engagement.

    Args:
        ares_api_url        — URL base de Ares (default: settings.ares_api_url)
        poll_interval_secs  — segundos entre polls (default: 30)
        http_client         — cliente httpx inyectable (para tests)
        centinela_feed      — callback(source_ip, features) para alimentar Centinela
        cci_critical_threshold — umbral para trigger automático (default: 0.75)
    """

    def __init__(
        self,
        ares_api_url: str = settings.ares_api_url,
        poll_interval_secs: int = 30,
        http_client: Optional[Any] = None,
        centinela_feed: Optional[CentinelaFeedFn] = None,
        cci_critical_threshold: float = 0.75,
    ) -> None:
        from pantheon.guards.circuit_breaker import CircuitBreaker
        self._url = ares_api_url.rstrip("/")
        self._interval = poll_interval_secs
        self._http = http_client
        self._centinela_feed = centinela_feed
        self._cci_threshold = cci_critical_threshold
        self._last_poll: datetime = datetime.now(timezone.utc)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._errors: list[str] = []
        self._processed_count: int = 0
        # Circuit breaker: se abre tras N fallos HTTP consecutivos
        self._cb = CircuitBreaker(
            rate_limit=settings.ares_poll_cb_failures,
            window_secs=60.0,
            cooldown_secs=120.0,
        )

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ares-bridge-worker"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def poll_once(self) -> list[dict]:
        """
        Ejecuta un ciclo de polling manual. Útil para tests y llamadas síncronas.

        Returns:
            Lista de registros nuevos procesados en este ciclo.
        """
        since_iso = self._last_poll.isoformat()
        records = self._fetch_escalated(since_iso)
        processed = []
        for record in records:
            try:
                self._process_record(record)
                processed.append(record)
            except Exception as exc:
                self._errors.append(f"{datetime.now(timezone.utc).isoformat()}: {exc}")
        if records:
            self._last_poll = datetime.now(timezone.utc)
        return processed

    @property
    def processed_count(self) -> int:
        return self._processed_count

    @property
    def last_errors(self) -> list[str]:
        return list(self._errors[-10:])

    def _run(self) -> None:
        while self._running:
            try:
                self.poll_once()
            except Exception as exc:
                self._errors.append(str(exc))
            time.sleep(self._interval)

    def _fetch_escalated(self, since_iso: str) -> list[dict]:
        """
        Llama a GET {ARES_API_URL}/purple/escalated?since=<ISO>.

        Si el circuit breaker está abierto (demasiados fallos recientes),
        omite la llamada HTTP y devuelve lista vacía.
        """
        from pantheon.core.metrics import ARES_POLLS_TOTAL
        self._cb.tick()
        if self._cb.is_open:
            ARES_POLLS_TOTAL.labels(status="cb_open").inc()
            return []

        endpoint = f"{self._url}/purple/escalated"
        try:
            if self._http is not None:
                response = self._http.get(endpoint, params={"since": since_iso}, timeout=10)
                response.raise_for_status()
                result = response.json().get("escalated", [])
            else:
                import httpx
                with httpx.Client(timeout=10) as client:
                    r = client.get(endpoint, params={"since": since_iso})
                    r.raise_for_status()
                    result = r.json().get("escalated", [])
            ARES_POLLS_TOTAL.labels(status="ok").inc()
            return result
        except Exception as exc:
            self._errors.append(f"fetch error: {exc}")
            self._cb.record_ambiguous()   # cuenta como fallo
            ARES_POLLS_TOTAL.labels(status="error").inc()
            return []

    def _process_record(self, record: dict) -> None:
        """Convierte un record de Ares y alimenta Centinela."""
        features = ares_finding_to_anomaly(record)
        target_ip = record.get("target", "0.0.0.0")

        if self._centinela_feed is not None:
            self._centinela_feed(target_ip, features)

        # también registrar en el store local
        try:
            payload = {
                "hypothesis_id": f"ares-{record.get('scan_id', 'unknown')}",
                "source_ip":     target_ip,
                "ttp_tags":      _extract_ttp_tags(record),
                "severity":      _icc_to_severity(float(record.get("icc", 0.5))),
                "narrative":     _build_narrative(record),
                "ares_source":   "localhost",
            }
            receive_escalated(payload)
        except PurpleBridgeError:
            pass   # duplicados silenciados; el vector ya fue enviado a Centinela

        self._processed_count += 1


# ── Helpers de conversión ─────────────────────────────────────────────────────

def _icc_to_severity(icc: float) -> str:
    if icc < 0.3:
        return "critical"
    if icc < 0.45:
        return "high"
    if icc < 0.55:
        return "moderate"
    return "low"


def _extract_ttp_tags(record: dict) -> list[str]:
    """Infiere TTPs MITRE probables a partir del fingerprint de Ares."""
    findings = record.get("findings", [])
    ttps = []
    ports = {f.get("port") for f in findings if f.get("state") == "open"}

    if record.get("adversarial"):
        ttps.append("T1036")     # Masquerading (evasión detectada)
    if 22 in ports:
        ttps.append("T1021")     # Remote Services (SSH)
    if any(p in ports for p in (445, 139)):
        ttps.append("T1021")     # SMB lateral movement
    if any(p in ports for p in (80, 443, 8080)):
        ttps.append("T1190")     # Exploit Public-Facing Application
    if any(f.get("severity") in ("high", "critical") for f in findings):
        ttps.append("T1595")     # Active Scanning → exploit

    return list(dict.fromkeys(ttps))   # deduplicado


def _build_narrative(record: dict) -> str:
    findings = record.get("findings", [])
    target = record.get("target", "unknown")
    icc = record.get("icc", 0.0)
    adversarial = record.get("adversarial", False)
    high_risk = sum(1 for f in findings if f.get("severity") in ("high", "critical"))

    adv_note = " con comportamiento evasivo detectado por Isolation Forest" if adversarial else ""
    return (
        f"Escalado de Ares v3.2: scan sobre {target}{adv_note}. "
        f"ICC={icc:.3f} (umbral=0.55). "
        f"{len(findings)} findings, {high_risk} de alta severidad. "
        f"engagement_id={record.get('engagement_id', 'n/a')}"
    )

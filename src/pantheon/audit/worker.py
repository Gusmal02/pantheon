"""
Worker del patrón Transactional Outbox para Audit Trail.

Ejecuta en un hilo o proceso independiente. Cada N segundos:
  1. Lee los registros de audit_trail con replicated=FALSE.
  2. Para cada uno: escribe al pre-commit log (con fsync).
  3. Replica a WORM S3.
  4. Marca replicated=TRUE en PostgreSQL.

Si el pre-commit log o WORM fallan, el registro queda replicated=FALSE
y se reintentará en el siguiente ciclo — nunca se pierde el evento ACID.
"""

import hashlib
import logging
import threading
import time
from typing import Optional

import psycopg2

from pantheon.audit.enclave import PreCommitLog
from pantheon.audit.trail import AuditTrail
from pantheon.audit.worm import WORMError, replicate_to_worm
from pantheon.core.config import settings

logger = logging.getLogger(__name__)

_PANTHEON_SESSION = "pantheon-global"


class OutboxWorker:
    """
    Worker que procesa los registros pendientes del Audit Trail.

    Args:
        conn         — conexión PostgreSQL (se puede reusar; el worker no es async)
        poll_secs    — intervalo entre ciclos (default: settings.pantheon_outbox_poll_secs)
        session_id   — ID de sesión para el PreCommitLog y WORM
    """

    def __init__(
        self,
        conn: psycopg2.extensions.connection,
        poll_secs: int = settings.pantheon_outbox_poll_secs,
        session_id: str = _PANTHEON_SESSION,
    ) -> None:
        self._conn = conn
        self._poll_secs = poll_secs
        self._session_id = session_id
        self._trail = AuditTrail(conn)
        self._log = PreCommitLog(session_id=session_id)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Lanza el worker en un hilo daemon."""
        self._thread = threading.Thread(target=self._run, daemon=True, name="outbox-worker")
        self._thread.start()
        logger.info("OutboxWorker iniciado (poll=%ds)", self._poll_secs)

    def stop(self, timeout: float = 10.0) -> None:
        """Detiene el worker ordenadamente."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("OutboxWorker detenido")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._process_batch()
            except Exception:
                logger.exception("Error en ciclo OutboxWorker")
            self._stop_event.wait(timeout=self._poll_secs)

    def _process_batch(self) -> None:
        records = self._trail.get_unreplicated(limit=50)
        if not records:
            return

        for record in records:
            try:
                entry = self._log.write(
                    entry_id=record.id,
                    action=record.event_type,
                    operator_id=record.operator_id,
                )

                replicate_to_worm(
                    entry_id=record.id,
                    session_id=self._session_id,
                    chain_hash=record.chain_hash,
                    payload={
                        "event_type":  record.event_type,
                        "operator_id": record.operator_id,
                        "details":     record.details,
                        "timestamp":   record.timestamp,
                        "approved":    record.approved,
                    },
                )

                pre_commit_hash = hashlib.sha256(
                    f"{entry.chain_hash}:{entry.hmac_sig}".encode()
                ).hexdigest()

                self._trail.mark_replicated(record.id, pre_commit_hash)
                logger.debug("Replicado: %s", record.id)

            except WORMError as exc:
                logger.error("WORM falló para %s: %s — se reintentará", record.id, exc)
            except Exception:
                logger.exception("Error procesando registro %s", record.id)

    def process_once(self) -> int:
        """Ejecuta un único ciclo de procesamiento (útil para tests)."""
        records = self._trail.get_unreplicated(limit=50)
        self._process_batch()
        return len(records)

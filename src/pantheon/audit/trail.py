"""
Audit Trail con patrón Transactional Outbox.

La novedad de Pantheon respecto a Ares: la escritura al pre-commit log y la
réplica WORM NO ocurren síncronamente en el path de negocio. En su lugar:

  1. record_event() inserta en audit_trail con replicated=FALSE dentro de la
     misma transacción ACID que la operación que la genera.
  2. El worker independiente (audit/worker.py) lee los registros con
     replicated=FALSE, genera el pre-commit log y hace PUT WORM, y solo
     entonces marca replicated=TRUE.

Esto garantiza que la cadena de hashes nunca se rompe aunque el proceso caiga
entre pasos (la transacción primaria se hace atómica con la operación).
"""

import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import psycopg2
import psycopg2.extras

from pantheon.core.config import settings


class EventType(str, Enum):
    HYPOTHESIS_GENERATED = "hypothesis_generated"
    CONTENTION_APPROVED  = "contention_approved"
    CONTENTION_REJECTED  = "contention_rejected"
    CONTENTION_TIMEOUT   = "contention_timeout"
    PLAYBOOK_VALIDATED   = "playbook_validated"
    PLAYBOOK_BLOCKED     = "playbook_blocked"
    EMERGENCY_ISOLATION  = "emergency_isolation"
    FEEDBACK_RECEIVED    = "feedback_received"
    INPUT_GUARD_BLOCKED  = "input_guard_blocked"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    KILL_SWITCH_TRIGGERED = "kill_switch_triggered"


@dataclass
class AuditRecord:
    id: str
    event_type: str
    operator_id: str
    details: dict
    chain_hash: str
    timestamp: str
    jit_pin: str
    approved: bool
    replicated: bool = False
    pre_commit_hash: str = ""


def _compute_chain_hash(
    action: str,
    timestamp: str,
    operator_id: str,
    nonce: str,
    previous_hash: str,
) -> str:
    raw = f"{action}|{timestamp}|{operator_id}|{nonce}|{previous_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


class AuditTrail:
    """
    Escribe eventos de auditoría en PostgreSQL con hash encadenado.

    Uso:
        trail = AuditTrail(conn)
        trail.record_event(
            event_type=EventType.HYPOTHESIS_GENERATED,
            operator_id="op_42",
            details={"hypothesis": "..."},
            approved=False,
        )

    El worker de Outbox (audit/worker.py) se encarga de replicar
    los registros con replicated=FALSE al pre-commit log y WORM.
    """

    def __init__(self, conn: psycopg2.extensions.connection) -> None:
        self._conn = conn
        self._last_hash: Optional[str] = None

    def _get_last_hash(self) -> str:
        if self._last_hash is not None:
            return self._last_hash
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT chain_hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                self._last_hash = row[0]
                return self._last_hash
        # primer registro: semilla del hash de configuración
        seed = hashlib.sha256(
            f"genesis:pantheon:{settings.postgres_db}".encode()
        ).hexdigest()
        self._last_hash = seed
        return self._last_hash

    def record_event(
        self,
        event_type: EventType,
        operator_id: str,
        details: dict,
        approved: bool = False,
        jit_pin: str = "",
        cursor: Optional[psycopg2.extensions.cursor] = None,
    ) -> AuditRecord:
        """
        Inserta un evento en audit_trail con replicated=FALSE.

        Si se pasa un cursor activo (cursor), usa esa transacción existente
        para garantizar atomicidad con la operación que genera el evento.
        Si no, abre una transacción propia.

        Returns:
            AuditRecord con el chain_hash calculado.
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = secrets.token_hex(16)
        previous_hash = self._get_last_hash()

        chain_hash = _compute_chain_hash(
            action=event_type.value if isinstance(event_type, EventType) else event_type,
            timestamp=timestamp,
            operator_id=operator_id,
            nonce=nonce,
            previous_hash=previous_hash,
        )

        record = AuditRecord(
            id=entry_id,
            event_type=event_type.value if isinstance(event_type, EventType) else event_type,
            operator_id=operator_id,
            details=details,
            chain_hash=chain_hash,
            timestamp=timestamp,
            jit_pin=jit_pin,
            approved=approved,
            replicated=False,
        )

        details_json = json.dumps(details)

        def _insert(cur: psycopg2.extensions.cursor) -> None:
            cur.execute(
                """
                INSERT INTO audit_trail
                    (id, event_type, operator_id, details, chain_hash,
                     pre_commit_hash, timestamp, jit_pin, approved, replicated)
                VALUES
                    (%s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, FALSE)
                """,
                (
                    entry_id,
                    record.event_type,
                    operator_id,
                    details_json,
                    chain_hash,
                    "",
                    timestamp,
                    jit_pin,
                    approved,
                ),
            )

        if cursor is not None:
            _insert(cursor)
        else:
            with self._conn.cursor() as cur:
                _insert(cur)
            self._conn.commit()

        self._last_hash = chain_hash
        return record

    def get_unreplicated(self, limit: int = 50) -> list[AuditRecord]:
        """Devuelve los registros pendientes de replicación (para el worker Outbox)."""
        with self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """
                SELECT id, event_type, operator_id, details, chain_hash,
                       pre_commit_hash, timestamp, jit_pin, approved, replicated
                FROM audit_trail
                WHERE replicated = FALSE
                ORDER BY timestamp ASC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()

        return [
            AuditRecord(
                id=str(row["id"]),
                event_type=row["event_type"],
                operator_id=row["operator_id"],
                details=row["details"] if isinstance(row["details"], dict) else json.loads(row["details"]),
                chain_hash=row["chain_hash"],
                pre_commit_hash=row["pre_commit_hash"] or "",
                timestamp=row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
                jit_pin=row["jit_pin"] or "",
                approved=bool(row["approved"]),
                replicated=bool(row["replicated"]),
            )
            for row in rows
        ]

    def mark_replicated(self, entry_id: str, pre_commit_hash: str) -> None:
        """El worker Outbox llama a este método tras confirmar pre-commit log + WORM."""
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE audit_trail SET replicated = TRUE, pre_commit_hash = %s WHERE id = %s",
                (pre_commit_hash, entry_id),
            )
        self._conn.commit()

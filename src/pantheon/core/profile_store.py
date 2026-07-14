"""
Persistencia de perfiles IPCA en PostgreSQL.

Carga y guarda OperatorProfile en la tabla `operators` (ya creada por init_db.py).
Si PostgreSQL no está disponible, falla silenciosamente y devuelve None en load().
"""

from __future__ import annotations

import logging
from typing import Optional

from pantheon.core.config import settings

logger = logging.getLogger(__name__)


def _connect():
    import psycopg2
    return psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        dbname=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=2,
    )


class ProfileStore:
    """
    Almacén de perfiles OperatorProfile respaldado por PostgreSQL.

    Uso:
        store = ProfileStore()
        profile = store.load("op_001")    # None si no existe o DB no disponible
        store.save("op_001", profile)     # no-op si DB no disponible
    """

    def __init__(self) -> None:
        self._available = self._ping()

    def _ping(self) -> bool:
        try:
            conn = _connect()
            conn.close()
            return True
        except Exception as exc:
            logger.debug("ProfileStore: PostgreSQL no disponible: %s", exc)
            return False

    def load(self, operator_id: str):
        """
        Carga un OperatorProfile desde PostgreSQL.

        Returns:
            OperatorProfile si existe, None en caso contrario.
        """
        if not self._available:
            return None
        try:
            from pantheon.acme.ipca import OperatorProfile
            conn = _connect()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT ipca_state FROM operators "
                    "WHERE operator_id = %s AND ipca_state IS NOT NULL",
                    (operator_id,),
                )
                row = cur.fetchone()
            conn.close()
            if row and row[0]:
                return OperatorProfile.deserialize(bytes(row[0]), operator_id)
        except Exception as exc:
            logger.warning("ProfileStore.load('%s') error: %s", operator_id, exc)
        return None

    def save(self, operator_id: str, profile) -> None:
        """Guarda un OperatorProfile en PostgreSQL (upsert)."""
        if not self._available:
            return
        try:
            import psycopg2
            conn = _connect()
            blob = psycopg2.Binary(profile.serialize())
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO operators
                            (operator_id, ipca_state, calibrated, feedback_count)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (operator_id) DO UPDATE
                            SET ipca_state     = EXCLUDED.ipca_state,
                                calibrated     = EXCLUDED.calibrated,
                                feedback_count = EXCLUDED.feedback_count,
                                last_active    = NOW()
                        """,
                        (operator_id, blob, profile.is_calibrated, profile.feedback_count),
                    )
            conn.close()
        except Exception as exc:
            logger.warning("ProfileStore.save('%s') error: %s", operator_id, exc)

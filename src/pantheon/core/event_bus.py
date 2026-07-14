"""
Event Bus de Pantheon sobre Redis Streams + Kill Switch Pub/Sub.

Streams:
  STREAM_EVENTS  — eventos anomalía de Centinela → Hermes
  STREAM_DECISIONS — decisiones de hipótesis Hermes → War Room
  CHANNEL_KILL   — Pub/Sub; cualquier mensaje aborta todos los listeners

El Kill Switch de Pantheon es independiente del de Ares (canal diferente)
para evitar que un kill switch de pentesting detenga el hunting defensivo.
"""

import json
import threading
from typing import Callable, Optional

import redis

STREAM_EVENTS    = "pantheon:events"
STREAM_DECISIONS = "pantheon:decisions"
CHANNEL_KILL     = "pantheon:killswitch"


def get_client(url: Optional[str] = None) -> redis.Redis:
    from pantheon.core.config import settings
    resolved = url or settings.redis_url
    return redis.Redis.from_url(resolved, decode_responses=True)


def publish_event(event: dict, client: redis.Redis) -> str:
    """Publica un evento anomalía de Centinela en el stream de eventos."""
    return client.xadd(STREAM_EVENTS, {"payload": json.dumps(event)})


def publish_decision(decision: dict, client: redis.Redis) -> str:
    """Publica la decisión de hipótesis de Hermes hacia el War Room."""
    return client.xadd(STREAM_DECISIONS, {"payload": json.dumps(decision)})


def read_events(
    client: redis.Redis,
    last_id: str = "$",
    block_ms: int = 1000,
    count: int = 10,
) -> list[tuple[str, dict]]:
    """Lee eventos del stream con block (para uso en consumer loop)."""
    results = client.xread(
        {STREAM_EVENTS: last_id},
        count=count,
        block=block_ms,
    )
    if not results:
        return []
    entries = []
    for _stream, messages in results:
        for msg_id, fields in messages:
            payload = json.loads(fields["payload"])
            entries.append((msg_id, payload))
    return entries


class KillSwitch:
    """
    Escucha en CHANNEL_KILL y llama a abort_callback en cualquier mensaje.
    Thread-safe; el hilo es daemon (no bloquea el cierre del proceso).
    """

    def __init__(self, client: redis.Redis, abort_callback: Callable[[], None]) -> None:
        self._client   = client
        self._callback = abort_callback
        self._pubsub   = client.pubsub()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._pubsub.subscribe(**{CHANNEL_KILL: self._handle})
        self._thread = self._pubsub.run_in_thread(sleep_time=0.01, daemon=True)

    def stop(self) -> None:
        if self._thread:
            self._thread.stop()
        self._pubsub.unsubscribe(CHANNEL_KILL)

    def _handle(self, message: dict) -> None:
        if message["type"] == "message":
            self._callback()

    @staticmethod
    def trigger(client: redis.Redis, reason: str = "manual") -> int:
        """Emite señal de aborto. Devuelve el número de suscriptores notificados."""
        return client.publish(CHANNEL_KILL, reason)

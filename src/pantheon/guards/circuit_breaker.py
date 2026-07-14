"""
Circuit Breaker para el Input Guard.

Si los eventos AMBIGUOUS superan INPUT_GUARD_RATE_LIMIT en 10 segundos,
el circuit breaker se ABRE: desactiva la verificación LLM secundaria y
activa el modo de contingencia (cuarentena de logs para triaje humano).

El circuit breaker se CIERRA de nuevo cuando la tasa de eventos ambiguos
permanece por debajo del umbral durante INPUT_GUARD_CB_COOLDOWN_SECS
segundos consecutivos.

Estados:
  CLOSED  → operación normal (verificación LLM activa)
  OPEN    → modo contingencia (cuarentena, sin LLM)
  HALF    → período de cooldown monitoreando recuperación
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CBState(str, Enum):
    CLOSED = "closed"   # normal
    OPEN   = "open"     # contingencia activa
    HALF   = "half"     # cooldown, monitoreando


@dataclass
class CircuitBreakerStats:
    state: CBState
    ambiguous_count_in_window: int
    rate_limit: int
    window_secs: float
    cooldown_secs: float
    open_count: int   # cuántas veces se ha abierto


class CircuitBreaker:
    """
    Circuit breaker para el Input Guard.

    Thread-safe: todos los accesos a estado interno están bajo _lock.

    Args:
        rate_limit    — eventos ambiguos por ventana antes de abrir
        window_secs   — duración de la ventana de medición (default 10s)
        cooldown_secs — segundos de tasa baja antes de cerrar (default 30s)
    """

    def __init__(
        self,
        rate_limit: int = 50,
        window_secs: float = 10.0,
        cooldown_secs: float = 30.0,
    ) -> None:
        self._rate_limit   = rate_limit
        self._window_secs  = window_secs
        self._cooldown_secs = cooldown_secs

        self._state        = CBState.CLOSED
        self._event_times: list[float] = []
        self._open_count   = 0
        self._state_since  = time.monotonic()
        self._lock         = threading.Lock()

    # ── API pública ───────────────────────────────────────────────────────────

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._state == CBState.OPEN

    @property
    def state(self) -> CBState:
        with self._lock:
            return self._state

    def record_ambiguous(self) -> None:
        """Registra un evento ambiguo. Puede abrir el circuit breaker."""
        with self._lock:
            now = time.monotonic()
            self._event_times.append(now)
            # limpiar eventos fuera de la ventana
            cutoff = now - self._window_secs
            self._event_times = [t for t in self._event_times if t >= cutoff]

            if self._state == CBState.CLOSED:
                if len(self._event_times) > self._rate_limit:
                    self._state = CBState.OPEN
                    self._state_since = now
                    self._open_count += 1

            elif self._state == CBState.HALF:
                # cualquier evento ambiguoso en HALF vuelve a OPEN
                if len(self._event_times) > self._rate_limit:
                    self._state = CBState.OPEN
                    self._state_since = now
                    self._open_count += 1

    def tick(self) -> None:
        """
        Llamar periódicamente (ej. cada segundo) para gestionar transiciones:
          OPEN → HALF después de cooldown_secs sin eventos.
          HALF → CLOSED si permanece limpio cooldown_secs más.
        """
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_secs
            self._event_times = [t for t in self._event_times if t >= cutoff]
            recent = len(self._event_times)

            if self._state == CBState.OPEN:
                elapsed = now - self._state_since
                # OPEN→HALF: solo necesita que haya pasado el cooldown
                if elapsed >= self._cooldown_secs:
                    self._state = CBState.HALF
                    self._state_since = now

            elif self._state == CBState.HALF:
                elapsed = now - self._state_since
                # HALF→CLOSED: cooldown transcurrido Y tasa de eventos baja
                if elapsed >= self._cooldown_secs and recent == 0:
                    self._state = CBState.CLOSED
                    self._state_since = now

    def reset(self) -> None:
        """Reinicia manualmente el circuit breaker (para tests o administración)."""
        with self._lock:
            self._state = CBState.CLOSED
            self._event_times = []
            self._state_since = time.monotonic()

    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_secs
            recent = len([t for t in self._event_times if t >= cutoff])
            return CircuitBreakerStats(
                state=self._state,
                ambiguous_count_in_window=recent,
                rate_limit=self._rate_limit,
                window_secs=self._window_secs,
                cooldown_secs=self._cooldown_secs,
                open_count=self._open_count,
            )

"""Base para conectores de fuentes externas (Suricata, Wazuh, etc.)."""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ConnectorStatus:
    name: str
    type: str
    enabled: bool
    online: bool
    last_event_at: float | None
    events_total: int
    error: str
    config: dict


class BaseConnector(ABC):
    type: str = "base"

    def __init__(self, name: str, config: dict) -> None:
        self.name = name
        self._config = dict(config)
        self._enabled = False
        self._online = False
        self._last_event_at: float | None = None
        self._events_total = 0
        self._error = ""
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def enable(self) -> None:
        with self._lock:
            self._enabled = True
        self._stop.clear()
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._run_loop, daemon=True, name=f"connector-{self.name}"
            )
            self._thread.start()

    def disable(self) -> None:
        with self._lock:
            self._enabled = False
            self._online = False
        self._stop.set()

    def update_config(self, config: dict) -> None:
        with self._lock:
            self._config = dict(config)

    # ── loop interno ──────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                is_up = self._check_health()
                with self._lock:
                    self._online = is_up
                    if is_up:
                        self._error = ""
                if is_up:
                    self._ingest()
            except Exception as exc:
                with self._lock:
                    self._online = False
                    self._error = str(exc)[:200]
            poll = self._config.get("poll_interval_secs", 30)
            self._stop.wait(poll)

    # ── interfaz abstracta ────────────────────────────────────────────────────

    @abstractmethod
    def _check_health(self) -> bool:
        """True si el origen es alcanzable."""
        ...

    @abstractmethod
    def _ingest(self) -> None:
        """Lee nuevos eventos y los envía al pipeline."""
        ...

    @abstractmethod
    def test_connection(self) -> dict:
        """Test sincrónico. Retorna {ok, message, latency_ms}."""
        ...

    # ── status ────────────────────────────────────────────────────────────────

    def get_status(self) -> ConnectorStatus:
        with self._lock:
            safe = {
                k: ("***" if any(s in k.lower() for s in ("password", "key", "secret")) else v)
                for k, v in self._config.items()
            }
            return ConnectorStatus(
                name=self.name,
                type=self.type,
                enabled=self._enabled,
                online=self._online,
                last_event_at=self._last_event_at,
                events_total=self._events_total,
                error=self._error,
                config=safe,
            )

    # ── helper compartido ─────────────────────────────────────────────────────

    def _push(self, features: list[float], source_ip: str, log_text: str) -> None:
        from pantheon.core.pipeline import get_pipeline
        try:
            get_pipeline().process_event(
                features, source_ip, log_text,
                operator_id=f"connector:{self.name}",
            )
            with self._lock:
                self._events_total += 1
                self._last_event_at = time.time()
        except Exception:
            pass

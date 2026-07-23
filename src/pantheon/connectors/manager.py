"""ConnectorManager — singleton que gestiona todos los conectores de fuentes externas."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Dict

from pantheon.connectors.base import BaseConnector, ConnectorStatus
from pantheon.connectors.suricata import SuricataConnector
from pantheon.connectors.wazuh import WazuhConnector

_CLASSES: dict[str, type[BaseConnector]] = {
    "suricata": SuricataConnector,
    "wazuh":    WazuhConnector,
}

_DEFAULTS: dict[str, dict] = {
    "suricata": {
        "type": "suricata",
        "enabled": False,
        "config": {
            "eve_json_path": "/var/log/suricata/eve.json",
            "poll_interval_secs": 5,
            "stale_threshold_secs": 120,
        },
    },
    "wazuh": {
        "type": "wazuh",
        "enabled": False,
        "config": {
            "api_url": "https://localhost:55000",
            "username": "admin",
            "password": "",
            "poll_interval_secs": 30,
            "min_rule_level": 5,
            "verify_ssl": False,
        },
    },
}

# Config guardada en el directorio raíz del proyecto
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "connector_configs.json"

_shared: "ConnectorManager | None" = None
_shared_lock = threading.Lock()


def get_connector_manager() -> "ConnectorManager":
    global _shared
    if _shared is None:
        with _shared_lock:
            if _shared is None:
                _shared = ConnectorManager()
    return _shared


class ConnectorManager:
    """Gestiona el ciclo de vida y configuración de todos los conectores."""

    def __init__(self) -> None:
        self._connectors: dict[str, BaseConnector] = {}
        self._lock = threading.Lock()
        self._load()

    # ── persistencia ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        saved: dict = {}
        if _CONFIG_PATH.exists():
            try:
                saved = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                saved = {}

        for name, default in _DEFAULTS.items():
            entry = saved.get(name, default)
            cls = _CLASSES[default["type"]]
            conn = cls(name, entry.get("config", default["config"]))
            self._connectors[name] = conn
            if entry.get("enabled", False):
                conn.enable()

    def _save(self) -> None:
        data = {}
        for name, conn in self._connectors.items():
            st = conn.get_status()
            data[name] = {
                "type": st.type,
                "enabled": st.enabled,
                "config": conn._config,   # raw config (con password)
            }
        try:
            _CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── API pública ───────────────────────────────────────────────────────────

    def get_all_status(self) -> dict[str, ConnectorStatus]:
        with self._lock:
            return {name: conn.get_status() for name, conn in self._connectors.items()}

    def update_config(self, name: str, config: dict) -> None:
        with self._lock:
            if name not in self._connectors:
                raise KeyError(f"Conector desconocido: {name}")
            self._connectors[name].update_config(config)
            self._save()

    def toggle(self, name: str) -> bool:
        with self._lock:
            if name not in self._connectors:
                raise KeyError(f"Conector desconocido: {name}")
            conn = self._connectors[name]
        st = conn.get_status()
        if st.enabled:
            conn.disable()
        else:
            conn.enable()
        self._save()
        return not st.enabled

    def test(self, name: str) -> dict:
        with self._lock:
            if name not in self._connectors:
                return {"ok": False, "message": f"Conector desconocido: {name}", "latency_ms": 0}
            conn = self._connectors[name]
        return conn.test_connection()

    def get(self, name: str) -> BaseConnector | None:
        return self._connectors.get(name)

    def is_enabled(self, name: str) -> bool:
        conn = self._connectors.get(name)
        return conn is not None and conn.get_status().enabled

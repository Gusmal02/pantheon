"""Fuente OSINT: abuse.ch Feodo Tracker — botnet C2 IP blocklist.

Sin API key. Descarga la lista completa cada hora y consulta localmente.
URL: https://feodotracker.abuse.ch/downloads/ipblocklist.json
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

from pantheon.osint.sources.base import BaseOsintSource

logger = logging.getLogger(__name__)

_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_REFRESH_SECS = 3600  # 1 hora — la lista se actualiza con esa frecuencia


class FeodoTrackerSource(BaseOsintSource):
    """Consulta el blocklist de C2 de Feodo Tracker (Emotet, Dridex, TrickBot, etc.)."""

    name = "feodotracker"

    def __init__(self, timeout: int = 10) -> None:
        self._timeout = timeout
        self._blocklist: dict[str, dict] = {}   # ip → entry del JSON
        self._last_refresh: float = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        """Descarga la lista si el caché local expiró. Silencia errores de red."""
        if time.time() - self._last_refresh < _REFRESH_SECS:
            return
        try:
            r = httpx.get(_BLOCKLIST_URL, timeout=self._timeout, follow_redirects=True)
            r.raise_for_status()
            entries: list[dict] = r.json()
            new_bl = {e["ip_address"]: e for e in entries if e.get("ip_address")}
            with self._lock:
                self._blocklist = new_bl
                self._last_refresh = time.time()
            logger.info("FeodoTracker: %d C2 IPs cargadas", len(new_bl))
        except Exception as exc:
            logger.debug("FeodoTracker refresh falló: %s", exc)

    def lookup(self, ip: str) -> dict:
        self._refresh()
        with self._lock:
            entry = self._blocklist.get(ip)
        if entry is None:
            return {}
        return {
            "threat_score": 1.0,
            "is_known_malicious": True,
            "active_campaign": True,
            "categories": ["botnet_c2"],
            "country_code": entry.get("country", ""),
            "sources_hit": [self.name],
        }

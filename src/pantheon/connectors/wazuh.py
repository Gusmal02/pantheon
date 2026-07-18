"""Conector Wazuh — consulta la REST API y envía alertas al pipeline."""
from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.request
from typing import Any

from pantheon.connectors.base import BaseConnector


def _build_features(alert: dict) -> list[float]:
    level = alert.get("rule", {}).get("level", 0)
    agent_ip = alert.get("agent", {}).get("ip", "0.0.0.0")
    parts = agent_ip.split(".")
    ip_byte = int(parts[-1]) / 255 if parts and parts[-1].isdigit() else 0.0
    from datetime import datetime, timezone
    hour = datetime.now(timezone.utc).hour
    groups = alert.get("rule", {}).get("groups", [])
    is_auth = 1.0 if any("authentication" in g for g in groups) else 0.0
    is_malware = 1.0 if any("malware" in g for g in groups) else 0.0
    return [
        min(level, 15) / 15,
        ip_byte,
        0.0,
        0.0,
        is_auth,
        is_malware,
        hour / 24,
        0.0,
    ]


class WazuhConnector(BaseConnector):
    type = "wazuh"

    def __init__(self, name: str, config: dict) -> None:
        super().__init__(name, config)
        self._last_alert_id: str | None = None

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self._config.get("verify_ssl", False):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _auth_header(self) -> str:
        user = self._config.get("username", "admin")
        pwd = self._config.get("password", "")
        return "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()

    def _get(self, path: str, timeout: int = 5) -> Any:
        base = self._config.get("api_url", "").rstrip("/")
        req = urllib.request.Request(
            f"{base}{path}",
            headers={"Authorization": self._auth_header()},
        )
        with urllib.request.urlopen(req, context=self._ssl_ctx(), timeout=timeout) as resp:
            return json.loads(resp.read())

    def _check_health(self) -> bool:
        if not self._config.get("api_url"):
            with self._lock:
                self._error = "URL de API no configurada"
            return False
        try:
            self._get("/", timeout=4)
            return True
        except Exception as exc:
            with self._lock:
                self._error = str(exc)[:200]
            return False

    def _ingest(self) -> None:
        try:
            data = self._get("/alerts?limit=50&sort=-timestamp")
        except Exception:
            return
        items = data.get("data", {}).get("affected_items", [])
        min_level = self._config.get("min_rule_level", 5)
        for item in reversed(items):
            alert_id = item.get("id", "")
            if self._last_alert_id and alert_id == self._last_alert_id:
                break
            level = item.get("rule", {}).get("level", 0)
            if level < min_level:
                continue
            self._push(
                features=_build_features(item),
                source_ip=item.get("agent", {}).get("ip", "0.0.0.0"),
                log_text=item.get("rule", {}).get("description", "wazuh_alert"),
            )
        if items:
            self._last_alert_id = items[0].get("id")

    def test_connection(self) -> dict:
        t0 = time.time()
        if not self._config.get("api_url"):
            return {"ok": False, "message": "URL no configurada", "latency_ms": 0}
        try:
            data = self._get("/", timeout=5)
            latency = round((time.time() - t0) * 1000, 1)
            title = data.get("data", {}).get("title", "Wazuh API")
            return {"ok": True, "message": f"{title} — responde OK", "latency_ms": latency}
        except Exception as exc:
            return {"ok": False, "message": str(exc)[:200], "latency_ms": 0}

    def recent_alerts(self, hours: float = 1.0, host: str | None = None,
                      rule_level_min: int = 5) -> list[dict]:
        """Retorna alertas recientes para uso por MCP tools de Hermes."""
        try:
            data = self._get("/alerts?limit=100&sort=-timestamp")
        except Exception:
            return []
        items = data.get("data", {}).get("affected_items", [])
        results = []
        for item in items:
            level = item.get("rule", {}).get("level", 0)
            if level < rule_level_min:
                continue
            agent_ip = item.get("agent", {}).get("ip", "")
            agent_name = item.get("agent", {}).get("name", "")
            if host and host not in (agent_ip, agent_name):
                continue
            results.append({
                "timestamp": item.get("timestamp"),
                "agent_ip": agent_ip,
                "agent_name": agent_name,
                "rule_description": item.get("rule", {}).get("description"),
                "rule_level": level,
                "rule_groups": item.get("rule", {}).get("groups", []),
            })
        return results

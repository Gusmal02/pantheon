"""Conector Suricata — consume EVE JSON log y envía alertas al pipeline."""
from __future__ import annotations

import json
import time
from pathlib import Path

from pantheon.connectors.base import BaseConnector

# Vector de 8 features normalizado para Centinela
# [port/65535, bytes/65535, is_tcp, is_udp, severity/10, is_internal_src, is_internal_dst, hour/24]
_PROTO_MAP = {"TCP": (1.0, 0.0), "UDP": (0.0, 1.0)}


def _is_internal(ip: str) -> float:
    parts = ip.split(".")
    if len(parts) != 4:
        return 0.0
    try:
        a, b = int(parts[0]), int(parts[1])
        return 1.0 if (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)) else 0.0
    except ValueError:
        return 0.0


def _build_features(evt: dict) -> list[float]:
    port = evt.get("dest_port") or evt.get("src_port") or 0
    proto = evt.get("proto", "TCP").upper()
    is_tcp, is_udp = _PROTO_MAP.get(proto, (0.5, 0.5))
    sev = evt.get("alert", {}).get("severity", 2)
    src = evt.get("src_ip", "")
    dst = evt.get("dest_ip", "")
    from datetime import datetime, timezone
    hour = datetime.now(timezone.utc).hour
    payload = evt.get("flow", {}).get("pkts_toserver", 0) * 100
    return [
        min(port, 65535) / 65535,
        min(payload, 65535) / 65535,
        is_tcp,
        is_udp,
        min(sev, 10) / 10,
        _is_internal(src),
        _is_internal(dst),
        hour / 24,
    ]


class SuricataConnector(BaseConnector):
    type = "suricata"

    def __init__(self, name: str, config: dict) -> None:
        super().__init__(name, config)
        self._file_pos: int = 0   # posición en el archivo para tail eficiente

    def _eve_path(self) -> Path:
        return Path(self._config.get("eve_json_path", "/var/log/suricata/eve.json"))

    def _check_health(self) -> bool:
        p = self._eve_path()
        if not p.exists():
            with self._lock:
                self._error = f"Archivo no encontrado: {p}"
            return False
        stale_secs = self._config.get("stale_threshold_secs", 120)
        mtime = p.stat().st_mtime
        if time.time() - mtime > stale_secs:
            with self._lock:
                self._error = f"Sin actividad hace >{stale_secs}s"
            return False
        return True

    def _ingest(self) -> None:
        p = self._eve_path()
        try:
            size = p.stat().st_size
        except OSError:
            return

        # Reiniciar offset si el archivo fue rotado
        if size < self._file_pos:
            self._file_pos = 0

        if size == self._file_pos:
            return

        with open(p, encoding="utf-8", errors="replace") as fh:
            fh.seek(self._file_pos)
            new_pos = self._file_pos
            for line in fh:
                new_pos += len(line.encode("utf-8", errors="replace"))
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("event_type") != "alert":
                    continue
                self._push(
                    features=_build_features(evt),
                    source_ip=evt.get("src_ip", "0.0.0.0"),
                    log_text=evt.get("alert", {}).get("signature", "suricata_alert"),
                )
            self._file_pos = new_pos

    def test_connection(self) -> dict:
        t0 = time.time()
        p = self._eve_path()
        if not p.exists():
            return {"ok": False, "message": f"Archivo no encontrado: {p}", "latency_ms": 0}
        try:
            size = p.stat().st_size
            mtime = p.stat().st_mtime
            age = int(time.time() - mtime)
            return {
                "ok": True,
                "message": f"Archivo encontrado ({size} bytes, modificado hace {age}s)",
                "latency_ms": round((time.time() - t0) * 1000, 1),
            }
        except OSError as exc:
            return {"ok": False, "message": str(exc), "latency_ms": 0}

    def recent_alerts(self, hours: float = 1.0, ip: str | None = None,
                      signature_contains: str | None = None) -> list[dict]:
        """Retorna alertas recientes para uso por MCP tools de Hermes."""
        p = self._eve_path()
        if not p.exists():
            return []
        cutoff = time.time() - hours * 3600
        results: list[dict] = []
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if evt.get("event_type") != "alert":
                    continue
                src = evt.get("src_ip", "")
                dst = evt.get("dest_ip", "")
                sig = evt.get("alert", {}).get("signature", "")
                if ip and ip not in (src, dst):
                    continue
                if signature_contains and signature_contains.lower() not in sig.lower():
                    continue
                results.append({
                    "timestamp": evt.get("timestamp"),
                    "src_ip": src,
                    "dest_ip": dst,
                    "dest_port": evt.get("dest_port"),
                    "proto": evt.get("proto"),
                    "signature": sig,
                    "category": evt.get("alert", {}).get("category"),
                    "severity": evt.get("alert", {}).get("severity"),
                })
        return results[-50:]

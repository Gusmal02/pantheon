"""OsintAggregator — combina fuentes OSINT y cachea resultados por IP.

Flujo:
  1. Hermes llama query_osint(ip) vía MCP tool.
  2. Aggregator revisa caché en memoria (TTL configurable, default 1h).
  3. Si miss: consulta todas las fuentes disponibles en paralelo (threading).
  4. Combina resultados: score = max(), strings = primer valor no vacío.
  5. Guarda en caché y retorna ThreatContext.

Sin dependencia de Redis — caché in-process para no añadir complejidad operacional.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from pantheon.osint.models import ThreatContext
from pantheon.osint.sources.abuseipdb import AbuseIPDBSource
from pantheon.osint.sources.base import BaseOsintSource
from pantheon.osint.sources.feodotracker import FeodoTrackerSource

logger = logging.getLogger(__name__)


class OsintAggregator:
    def __init__(
        self,
        sources: list[BaseOsintSource] | None = None,
        cache_ttl_secs: int = 3600,
        request_timeout_secs: int = 5,
    ) -> None:
        if sources is None:
            from pantheon.core.config import settings
            sources = [
                FeodoTrackerSource(timeout=request_timeout_secs),
                AbuseIPDBSource(
                    api_key=settings.abuseipdb_api_key,
                    timeout=request_timeout_secs,
                ),
            ]
        self._sources = sources
        self._cache_ttl = cache_ttl_secs
        self._request_timeout = request_timeout_secs
        self._cache: dict[str, tuple[ThreatContext, float]] = {}
        self._lock = threading.Lock()

    def enrich(self, ip: str) -> ThreatContext:
        """Retorna ThreatContext para la IP dada. Usa caché si está vigente."""
        with self._lock:
            entry = self._cache.get(ip)
        if entry is not None:
            ctx, ts = entry
            if time.time() - ts < self._cache_ttl:
                return ctx.model_copy(update={"cached": True})

        merged: dict = {
            "ip": ip,
            "threat_score": 0.0,
            "is_known_malicious": False,
            "active_campaign": False,
            "categories": [],
            "country_code": "",
            "asn_org": "",
            "total_reports": 0,
            "sources_hit": [],
            "cached": False,
        }

        active = [s for s in self._sources if s.available]
        if not active:
            return ThreatContext(**merged)

        with ThreadPoolExecutor(max_workers=len(active)) as pool:
            futures = {pool.submit(s.lookup, ip): s.name for s in active}
            for fut in as_completed(futures, timeout=self._request_timeout + 1):
                try:
                    result = fut.result()
                except Exception as exc:
                    logger.debug("OSINT source %s error: %s", futures[fut], exc)
                    continue
                if not result:
                    continue
                merged["threat_score"] = max(merged["threat_score"], result.get("threat_score", 0.0))
                merged["is_known_malicious"] = merged["is_known_malicious"] or result.get("is_known_malicious", False)
                merged["active_campaign"] = merged["active_campaign"] or result.get("active_campaign", False)
                merged["total_reports"] = max(merged["total_reports"], result.get("total_reports", 0))
                if not merged["country_code"]:
                    merged["country_code"] = result.get("country_code", "")
                if not merged["asn_org"]:
                    merged["asn_org"] = result.get("asn_org", "")
                merged["categories"].extend(result.get("categories", []))
                merged["sources_hit"].extend(result.get("sources_hit", []))

        merged["categories"] = list(dict.fromkeys(merged["categories"]))
        merged["sources_hit"] = list(dict.fromkeys(merged["sources_hit"]))

        ctx = ThreatContext(**merged)
        with self._lock:
            self._cache[ip] = (ctx, time.time())

        logger.debug("OSINT enrich(%s): score=%.2f sources=%s", ip, ctx.threat_score, ctx.sources_hit)
        return ctx

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()


# ── Singleton ─────────────────────────────────────────────────────────────────

_aggregator: OsintAggregator | None = None
_agg_lock = threading.Lock()


def get_osint_aggregator() -> OsintAggregator:
    global _aggregator
    if _aggregator is None:
        with _agg_lock:
            if _aggregator is None:
                from pantheon.core.config import settings
                _aggregator = OsintAggregator(
                    cache_ttl_secs=settings.osint_cache_ttl_secs,
                    request_timeout_secs=settings.osint_request_timeout_secs,
                )
    return _aggregator

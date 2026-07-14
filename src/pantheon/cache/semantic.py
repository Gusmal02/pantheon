"""
Semantic Cache para Pantheon.

Evita gastar LLM en hipótesis ya computadas para anomalías similares.
El fingerprint de contexto combina:
  - vector de anomalía (Centinela output)
  - IDs de los top-k documentos recuperados (Ornith)
  - hash del template de prompt activo

Cache backend: Redis (TTL configurable).
Similitud: distancia coseno entre fingerprints vectoriales.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np


@dataclass
class CacheEntry:
    fingerprint: str          # hash del contexto
    ranked_hypotheses: list   # resultado serializable de AcmeRanker
    timestamp: float
    hit_count: int = 0


@dataclass
class CacheStats:
    hits: int
    misses: int
    entries: int
    hit_rate: float


class SemanticCache:
    """
    Cache semántico de hipótesis rankeadas.

    Usa Redis como backend. Si Redis no está disponible (dev/test),
    cae en un dict en memoria.

    Args:
        redis_client  — cliente Redis o None (usa dict en memoria)
        ttl_secs      — tiempo de vida de las entradas (default 3600s)
        sim_threshold — similitud coseno mínima para considerar hit (default 0.95)
    """

    def __init__(
        self,
        redis_client=None,
        ttl_secs: int = 3600,
        sim_threshold: float = 0.95,
    ) -> None:
        self._redis       = redis_client
        self._ttl         = ttl_secs
        self._threshold   = sim_threshold
        self._memory: dict[str, str] = {}   # fallback in-memory
        self._hits   = 0
        self._misses = 0
        self._key_prefix = "pantheon:cache:"

    # ── API pública ───────────────────────────────────────────────────────────

    def get(
        self,
        anomaly_vector: np.ndarray,
        doc_ids: list[str],
        prompt_template_hash: str,
    ) -> Optional[list]:
        """
        Busca en caché una respuesta para este contexto.

        Returns:
            Lista de hipótesis rankeadas si hay hit; None si miss.
        """
        fp = self._fingerprint(anomaly_vector, doc_ids, prompt_template_hash)
        raw = self._load(fp)
        if raw is None:
            self._misses += 1
            return None

        try:
            entry = CacheEntry(**json.loads(raw))
            entry.hit_count += 1
            self._save(fp, entry)
            self._hits += 1
            return entry.ranked_hypotheses
        except (json.JSONDecodeError, TypeError):
            self._misses += 1
            return None

    def put(
        self,
        anomaly_vector: np.ndarray,
        doc_ids: list[str],
        prompt_template_hash: str,
        ranked_hypotheses: list,
    ) -> str:
        """
        Almacena el resultado rankeado para este contexto.

        Returns:
            fingerprint de la entrada almacenada.
        """
        fp = self._fingerprint(anomaly_vector, doc_ids, prompt_template_hash)
        entry = CacheEntry(
            fingerprint=fp,
            ranked_hypotheses=ranked_hypotheses,
            timestamp=time.time(),
        )
        self._save(fp, entry)
        return fp

    def invalidate(self, fingerprint: str) -> None:
        key = self._key_prefix + fingerprint
        if self._redis:
            self._redis.delete(key)
        else:
            self._memory.pop(key, None)

    def stats(self) -> CacheStats:
        total = self._hits + self._misses
        return CacheStats(
            hits=self._hits,
            misses=self._misses,
            entries=len(self._memory) if not self._redis else -1,
            hit_rate=self._hits / total if total > 0 else 0.0,
        )

    # ── internos ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fingerprint(
        anomaly_vector: np.ndarray,
        doc_ids: list[str],
        prompt_template_hash: str,
    ) -> str:
        """SHA-256 del contexto normalizado."""
        vec_normalized = np.asarray(anomaly_vector, dtype=float)
        norm = np.linalg.norm(vec_normalized)
        if norm > 0:
            vec_normalized = vec_normalized / norm
        vec_bytes = vec_normalized.round(4).tobytes()
        doc_str = json.dumps(sorted(doc_ids))
        raw = vec_bytes + doc_str.encode() + prompt_template_hash.encode()
        return hashlib.sha256(raw).hexdigest()

    def _load(self, fingerprint: str) -> Optional[str]:
        key = self._key_prefix + fingerprint
        if self._redis:
            return self._redis.get(key)
        return self._memory.get(key)

    def _save(self, fingerprint: str, entry: CacheEntry) -> None:
        key = self._key_prefix + fingerprint
        serialized = json.dumps({
            "fingerprint":       entry.fingerprint,
            "ranked_hypotheses": entry.ranked_hypotheses,
            "timestamp":         entry.timestamp,
            "hit_count":         entry.hit_count,
        })
        if self._redis:
            self._redis.setex(key, self._ttl, serialized)
        else:
            self._memory[key] = serialized

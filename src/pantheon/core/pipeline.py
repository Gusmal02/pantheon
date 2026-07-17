"""
Pipeline principal de Pantheon v2.1.

Cadena: InputGuard → Centinela → Hermes → AcmeRanker

Diseñado como singleton thread-safe. La API REST llama a get_pipeline()
para obtener la instancia compartida.

Detección en frío (sin modelo entrenado): el AnomalyDetector hace auto-fit
con datos sintéticos benignos en la primera llamada, lo que permite que el
sistema arranque sin datos de entrenamiento previos.

Ornith (Qdrant): si no está disponible, Hermes usa un retriever vacío y
genera hipótesis desde ATT&CK únicamente.

Ollama: si está corriendo en localhost:11434, Hermes usa LLM real.
Si no, usa fallbacks deterministas.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from pantheon.acme.ranker import AcmeRanker
from pantheon.acme.stage1 import AcmeStage1
from pantheon.attck_graph.graph import ATTCKGraph, get_shared_graph
from pantheon.centinela.detector import AnomalyDetector
from pantheon.centinela.pipeline import CentinelaDetectionPipeline, NetworkEvent
from pantheon.core.metrics import (
    CCI_SCORE, EVENTS_PROCESSED, HERMES_ITERATIONS, HYPOTHESES_GENERATED,
)
from pantheon.guards.guard import GuardVerdict, InputGuard
from pantheon.hermes.agent import HermesAgent, HermesResult

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    session_id: str
    source_ip: str
    guard_verdict: str
    cci: float
    is_critical: bool
    hermes_result: Optional[HermesResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        hypotheses = []
        if self.hermes_result:
            for rh in self.hermes_result.hypotheses:
                hypotheses.append({
                    "id": rh.candidate.id,
                    "text": rh.candidate.text,
                    "score": round(rh.final_score, 4),
                    "rank": rh.rank,
                    "ttp_tags": rh.candidate.ttp_tags,
                })
        return {
            "accepted": self.error is None,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "guard_verdict": self.guard_verdict,
            "cci": round(self.cci, 4),
            "is_critical": self.is_critical,
            "hypotheses": hypotheses,
            "error": self.error,
        }


class PantheonPipeline:
    """
    Pipeline principal de Pantheon.

    Uso:
        pipeline = get_pipeline()
        result   = pipeline.process_event([0.1, 0.9, ...], "192.168.1.5")
        hyps     = pipeline.get_hypotheses("op_001")
    """

    def __init__(self, ranker: Optional[AcmeRanker] = None) -> None:
        self._guard     = InputGuard()
        self._attck     = get_shared_graph()  # singleton: comparte pesos con Ornith
        self._ranker    = ranker or AcmeRanker(stage1=AcmeStage1())
        self._detector  = self._load_or_create_detector()
        self._centinela = CentinelaDetectionPipeline(self._detector)
        self._hermes: Optional[HermesAgent] = None
        self._lock      = threading.Lock()
        # Caché de resultados: operator_id → deque[HermesResult]
        self._cache: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

    # ── API pública ───────────────────────────────────────────────────────────

    def process_event(
        self,
        features: list[float],
        source_ip: str,
        log_text: str = "",
        operator_id: str = "default",
    ) -> PipelineResult:
        """
        Procesa un evento de red a través del pipeline completo.

        Returns:
            PipelineResult con CCI, hipótesis y metadatos de la investigación.
        """
        import uuid
        session_id = uuid.uuid4().hex[:12]

        # 1. InputGuard
        if log_text:
            guard_result = self._guard.process(log_text, source_ip)
            EVENTS_PROCESSED.labels(verdict=guard_result.verdict.value).inc()
            if guard_result.verdict in (GuardVerdict.BLOCK, GuardVerdict.QUARANTINE):
                return PipelineResult(
                    session_id=session_id,
                    source_ip=source_ip,
                    guard_verdict=guard_result.verdict.value,
                    cci=0.0,
                    is_critical=False,
                    error=guard_result.reason,
                )
        EVENTS_PROCESSED.labels(verdict="pass").inc()

        # 2. Centinela
        try:
            event    = NetworkEvent(features=features, source_ip=source_ip)
            decision = self._centinela.process(event)
        except RuntimeError:
            # Detector no entrenado → auto-fit con datos benignos sintéticos
            self._auto_fit(len(features))
            event    = NetworkEvent(features=features, source_ip=source_ip)
            decision = self._centinela.process(event)

        cci = decision.cci_result.cci
        CCI_SCORE.observe(cci)

        # 3. Hermes (solo si Centinela manda a investigación)
        hermes_result = None
        if decision.should_send_to_hermes:
            try:
                hermes_result = self._get_hermes().investigate(event, operator_id)
                HYPOTHESES_GENERATED.inc(len(hermes_result.hypotheses))
                HERMES_ITERATIONS.observe(hermes_result.iterations)
                with self._lock:
                    self._cache[operator_id].appendleft(hermes_result)
            except Exception as exc:
                logger.warning("Hermes error en proceso de evento: %s", exc)

        return PipelineResult(
            session_id=session_id,
            source_ip=source_ip,
            guard_verdict="pass",
            cci=cci,
            is_critical=decision.is_critical,
            hermes_result=hermes_result,
        )

    def get_hypotheses(self, operator_id: str, limit: int = 10) -> list[dict]:
        """Devuelve las hipótesis rankeadas más recientes para el operador."""
        with self._lock:
            results = list(self._cache.get(operator_id, []))

        hypotheses: list[dict] = []
        for hr in results:
            for rh in hr.hypotheses:
                hypotheses.append({
                    "id": rh.candidate.id,
                    "text": rh.candidate.text,
                    "score": round(rh.final_score, 4),
                    "rank": rh.rank,
                    "ttp_tags": rh.candidate.ttp_tags,
                    "source_ip": hr.event.source_ip,
                    "session_id": hr.session_id,
                    "attck_suggestions": hr.attck_suggestions,
                    "grounded": hr.hypothesis_grounded,
                })
        # ordenar por score descendente y limitar
        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        return hypotheses[:limit]

    # ── Privado ───────────────────────────────────────────────────────────────

    def _get_hermes(self) -> HermesAgent:
        if self._hermes is None:
            llm = self._try_ollama()
            self._hermes = HermesAgent(
                attck_graph=self._attck,
                ranker=self._ranker,
                retriever=self._try_ornith_retriever(),
                llm=llm,
            )
        return self._hermes

    @staticmethod
    def _try_ollama():
        try:
            from pantheon.core.ollama_llm import OllamaLLM
            return OllamaLLM.try_create()
        except Exception:
            return None

    @staticmethod
    def _try_ornith_retriever():
        """Devuelve retriever de Ornith si Qdrant está disponible, sino vacío."""
        try:
            from pantheon.ornith.client import OrnithClient
            from pantheon.core.config import settings
            client = OrnithClient(
                host=settings.qdrant_host, port=settings.qdrant_port
            )
            def retriever(query: str, top_k: int) -> list[dict]:
                try:
                    results = client.search(query, top_k=top_k)
                    return [r.payload for r in results] if results else []
                except Exception:
                    return []
            return retriever
        except Exception:
            return lambda q, k: []

    @staticmethod
    def _load_or_create_detector() -> AnomalyDetector:
        from pathlib import Path
        model_path = Path("models/centinela.pkl")
        if model_path.exists():
            try:
                return AnomalyDetector.load(model_path)
            except Exception:
                pass
        return AnomalyDetector()

    def _auto_fit(self, n_features: int) -> None:
        """Fit con datos benignos sintéticos para arranque en frío."""
        rng = np.random.default_rng(42)
        X = rng.normal(0.5, 0.15, size=(200, n_features)).clip(0.0, 1.0)
        self._detector.fit(X.astype(float))
        # Sincronizar la referencia dentro de Centinela
        self._centinela._detector = self._detector
        logger.info(
            "AnomalyDetector: auto-fit con datos sintéticos (%d features). "
            "Reemplazar con uv run python scripts/train_centinela.py en producción.",
            n_features,
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_pipeline: Optional[PantheonPipeline] = None
_pipeline_lock = threading.Lock()


def get_pipeline() -> PantheonPipeline:
    """Devuelve el pipeline singleton, inicializándolo en la primera llamada."""
    global _pipeline
    if _pipeline is None:
        with _pipeline_lock:
            if _pipeline is None:
                _pipeline = PantheonPipeline()
    return _pipeline

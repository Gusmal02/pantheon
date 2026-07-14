"""
Pipeline completo de Centinela.

Combina AnomalyDetector + CCI + historial temporal para generar
una decisión de routing por cada evento de red:

  LOW_CONFIDENCE → triaje humano directo en War Room (sin pasar por Hermes)
  MODERATE       → pasa el evento a Hermes para generación de hipótesis
  CRITICAL       → pasa a Hermes + señalización urgente al War Room

También calcula D_centroid y C_temp a partir del historial almacenado.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from pantheon.centinela.cci import CCIOutcome, CCIResult, compute_cci
from pantheon.centinela.detector import AnomalyDetector
from pantheon.core.config import settings

# historial de eventos por IP para C_temp (ventana de 1 hora)
_TEMPORAL_WINDOW_SECS = 3600
_SIMILARITY_THRESHOLD = 0.80   # distancia Euclidiana normalizada


@dataclass
class NetworkEvent:
    """Representación mínima de un evento de red para Centinela."""
    features: list[float]          # vector numérico del evento
    source_ip: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class CentinelaDecision:
    event: NetworkEvent
    cci_result: CCIResult
    should_escalate_to_human: bool
    should_send_to_hermes: bool
    is_critical: bool


class CentinelaException(RuntimeError):
    """Error no recuperable en el pipeline de Centinela."""


class CentinelaDetectionPipeline:
    """
    Pipeline de detección de anomalías para Centinela.

    Args:
        detector         — modelo Isolation Forest entrenado
        attack_centroids — array (n_clusters, n_features) de centroides de ataques conocidos
        ambiguous_threshold — umbral CCI inferior (default: settings.cci_ambiguous_threshold)
        critical_threshold  — umbral CCI superior (default: settings.cci_critical_threshold)
    """

    def __init__(
        self,
        detector: AnomalyDetector,
        attack_centroids: Optional[np.ndarray] = None,
        ambiguous_threshold: float = settings.cci_ambiguous_threshold,
        critical_threshold: float = settings.cci_critical_threshold,
    ) -> None:
        self._detector = detector
        self._centroids = attack_centroids
        self._amb_threshold = ambiguous_threshold
        self._crit_threshold = critical_threshold
        # historial temporal: {source_ip: deque[(timestamp, features)]}
        self._history: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def process(self, event: NetworkEvent) -> CentinelaDecision:
        """Procesa un evento y devuelve la decisión de routing."""
        features = np.asarray(event.features, dtype=float)

        p_anomaly = self._detector.score(features)
        d_centroid_norm = self._compute_d_centroid(features)
        c_temp = self._compute_c_temp(event)

        self._history[event.source_ip].append((event.timestamp, features))

        cci_result = compute_cci(
            p_anomaly=p_anomaly,
            d_centroid_norm=d_centroid_norm,
            c_temp=c_temp,
            ambiguous_threshold=self._amb_threshold,
            critical_threshold=self._crit_threshold,
            source_ip=event.source_ip,
        )

        should_escalate = cci_result.outcome == CCIOutcome.LOW_CONFIDENCE
        is_critical = cci_result.outcome == CCIOutcome.CRITICAL
        send_to_hermes = not should_escalate

        return CentinelaDecision(
            event=event,
            cci_result=cci_result,
            should_escalate_to_human=should_escalate,
            should_send_to_hermes=send_to_hermes,
            is_critical=is_critical,
        )

    def _compute_d_centroid(self, features: np.ndarray) -> float:
        """Distancia normalizada al centroide de ataque más cercano."""
        if self._centroids is None or len(self._centroids) == 0:
            return 0.5  # sin centroides conocidos: confianza media

        dists = np.linalg.norm(self._centroids - features, axis=1)
        min_dist = float(dists.min())
        # normalizar con clip a [0, 1] usando un rango máximo heurístico
        max_expected = float(np.sqrt(len(features)) * 5)  # heurístico
        return min(1.0, min_dist / max(max_expected, 1e-9))

    def _compute_c_temp(self, event: NetworkEvent) -> float:
        """Fracción de eventos similares del mismo host en la ventana temporal."""
        now = event.timestamp
        history = self._history[event.source_ip]
        features = np.asarray(event.features, dtype=float)
        feat_norm = np.linalg.norm(features) or 1.0

        recent = [
            f for ts, f in history
            if now - ts <= _TEMPORAL_WINDOW_SECS
        ]
        if not recent:
            return 0.0

        similar = sum(
            1 for f in recent
            if np.linalg.norm(np.asarray(f, dtype=float) - features)
               / feat_norm <= (1.0 - _SIMILARITY_THRESHOLD)
        )
        return min(1.0, similar / len(recent))

    def update_centroids(self, centroids: np.ndarray) -> None:
        """Actualiza los centroides de ataques conocidos (llamar tras reentrenamiento)."""
        self._centroids = centroids

"""
Perfil IPCA (Incremental PCA) por analista para Acme Ranker Stage 2.

Cada operador tiene su propio IPCA que captura su estilo de evaluación
(agresividad, exhaustividad, sesgo hacia ciertos TTPs).

El modelo se actualiza solo con feedback firmado y verificado.
Si el feedback se desvía > 3σ del historial reciente del operador,
se marca como outlier y requiere confirmación explícita.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.decomposition import IncrementalPCA


@dataclass
class FeedbackVector:
    """Representación numérica de un feedback dimensional."""
    thumbs:         float  # 0 = down, 1 = up
    relevance:      float  # 1-5 normalizado a [0, 1]
    clarity:        float
    actionability:  float
    urgency:        float

    @classmethod
    def from_dict(cls, d: dict) -> "FeedbackVector":
        def _norm(v: int | float, max_val: float = 5.0) -> float:
            return float(v) / max_val

        thumbs = 1.0 if d.get("thumbs", "up") == "up" else 0.0
        return cls(
            thumbs=thumbs,
            relevance=_norm(d.get("relevance", 3)),
            clarity=_norm(d.get("clarity", 3)),
            actionability=_norm(d.get("actionability", 3)),
            urgency=_norm(d.get("urgency", 3)),
        )

    def to_array(self) -> np.ndarray:
        return np.array([
            self.thumbs,
            self.relevance,
            self.clarity,
            self.actionability,
            self.urgency,
        ], dtype=float)


class OutlierFeedback(ValueError):
    """El feedback se desvía más de 3σ del historial del operador."""


class OperatorProfile:
    """
    Perfil IPCA incremental de un analista.

    Args:
        operator_id       — ID del analista
        n_components      — dimensiones del espacio IPCA (default 2)
        outlier_threshold — desviaciones estándar para detectar outliers (default 3.0)
    """

    _CALIBRATION_SAMPLES = 5   # muestras mínimas para inicializar el IPCA

    def __init__(
        self,
        operator_id: str,
        n_components: int = 2,
        outlier_threshold: float = 3.0,
    ) -> None:
        self.operator_id    = operator_id
        self._n_components  = n_components
        self._threshold     = outlier_threshold
        self._ipca          = IncrementalPCA(n_components=n_components)
        self._history: list[np.ndarray] = []
        self._calibrated    = False
        # sliders de sesión (anulan temporalmente el perfil)
        self.session_aggressiveness: float = 0.5
        self.session_caution:        float = 0.5

    @property
    def is_calibrated(self) -> bool:
        return self._calibrated

    @property
    def feedback_count(self) -> int:
        return len(self._history)

    def update(self, feedback: FeedbackVector, force: bool = False) -> None:
        """
        Actualiza el perfil con un nuevo vector de feedback.

        Args:
            feedback — FeedbackVector verificado y firmado
            force    — si True, omite la comprobación de outlier (para tests)

        Raises:
            OutlierFeedback si el vector se desvía > threshold σ del historial.
        """
        vec = feedback.to_array()

        if not force and self._calibrated:
            self._check_outlier(vec)

        self._history.append(vec.copy())

        if len(self._history) >= self._CALIBRATION_SAMPLES:
            X = np.stack(self._history[-50:])  # últimos 50 como ventana deslizante
            if X.shape[0] >= self._n_components:
                self._ipca.partial_fit(X)
                self._calibrated = True

    def score_hypothesis(self, features: np.ndarray) -> float:
        """
        Devuelve un score de relevancia para una hipótesis dado el perfil del analista.
        Si el perfil no está calibrado, devuelve 0.5 (neutral).

        Args:
            features — vector de características de la hipótesis (n_features,)
        """
        if not self._calibrated:
            return 0.5

        try:
            # proyectar en el espacio IPCA del analista
            projected = self._ipca.transform(features.reshape(1, -1))[0]
            # combinar con sliders de sesión
            base_score = float(np.clip(np.mean(np.abs(projected)), 0.0, 1.0))
            adjusted = (
                base_score
                * self.session_aggressiveness
                + (1.0 - base_score)
                * (1.0 - self.session_caution)
            )
            return float(np.clip(adjusted, 0.0, 1.0))
        except Exception:
            return 0.5

    def _check_outlier(self, vec: np.ndarray) -> None:
        if len(self._history) < 3:
            return
        history_arr = np.stack(self._history)
        mean = history_arr.mean(axis=0)
        std  = history_arr.std(axis=0) + 1e-9
        z    = np.abs((vec - mean) / std)
        if z.max() > self._threshold:
            raise OutlierFeedback(
                f"Feedback outlier detectado (z={z.max():.2f} > {self._threshold}). "
                "Confirmar antes de incorporar al perfil."
            )

    def serialize(self) -> bytes:
        return pickle.dumps({
            "ipca":        self._ipca,
            "history":     self._history,
            "calibrated":  self._calibrated,
            "n_components": self._n_components,
        })

    @classmethod
    def deserialize(cls, data: bytes, operator_id: str) -> "OperatorProfile":
        state = pickle.loads(data)
        profile = cls(operator_id=operator_id, n_components=state["n_components"])
        profile._ipca       = state["ipca"]
        profile._history    = state["history"]
        profile._calibrated = state["calibrated"]
        return profile

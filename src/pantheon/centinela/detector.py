"""
Centinela — detector de anomalías con Isolation Forest.

Flujo:
  1. fit(X) — entrena el Isolation Forest sobre tráfico benigno histórico.
  2. score(x) → p_anomaly en [0, 1] — cuanto más alto, más anómalo.
  3. El pipeline completo en pipeline.py combina score() con CCI y
     decide si el evento va a Hermes, a triaje humano o al war room crítico.

El modelo se entrena una vez (offline) y se serializa con joblib.
En producción se puede reentrenar periódicamente con tráfico nuevo.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Wrapper sobre Isolation Forest para Centinela.

    Uso:
        detector = AnomalyDetector()
        detector.fit(X_train)          # X_train: array (n_samples, n_features)
        score = detector.score(x)      # x: array (n_features,) → float en [0,1]
        detector.save("model.pkl")
        detector = AnomalyDetector.load("model.pkl")
    """

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.05,
        random_state: int = 42,
    ) -> None:
        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, X: np.ndarray) -> None:
        """Entrena el Isolation Forest sobre la muestra de tráfico benigno."""
        self._model.fit(X)
        self._fitted = True

    def score(self, x: np.ndarray) -> float:
        """
        Devuelve p_anomaly en [0, 1].

        Isolation Forest devuelve scores en [-1, 0] (más negativo = más anómalo).
        Los normalizamos a [0, 1] invirtiendo el signo y reescalando.
        El decision_function devuelve valores en (~-0.5, ~0.5); usamos
        clip + normalización lineal.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector no entrenado. Llama a fit() primero.")

        x_arr = np.asarray(x).reshape(1, -1)
        raw = self._model.decision_function(x_arr)[0]
        # decision_function: valores negativos más bajos = más anómalo
        # invertimos y escalamos a [0, 1] usando rango típico [-0.5, 0.5]
        p_anomaly = 1.0 - (np.clip(raw, -0.5, 0.5) + 0.5)
        return float(np.clip(p_anomaly, 0.0, 1.0))

    def predict_batch(self, X: np.ndarray) -> list[float]:
        """Devuelve scores para un batch de eventos."""
        if not self._fitted:
            raise RuntimeError("AnomalyDetector no entrenado.")
        raw = self._model.decision_function(X)
        scores = 1.0 - (np.clip(raw, -0.5, 0.5) + 0.5)
        return [float(s) for s in np.clip(scores, 0.0, 1.0)]

    def save(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self._model, f)
        self._fitted = True

    @classmethod
    def load(cls, path: Path | str) -> "AnomalyDetector":
        detector = cls()
        with open(path, "rb") as f:
            detector._model = pickle.load(f)
        detector._fitted = True
        return detector

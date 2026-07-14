"""
Acme Ranker Stage 1 — LightGBM contextual.

Ordena hipótesis por:
  - Similitud de fingerprint con episodios históricos relevantes
  - Relevancia temporal (episodios recientes pesan más)
  - Éxito histórico de playbooks similares (feedback positivo previo)

El modelo LightGBM se entrena con pares (hipótesis, score) donde el score
refleja el feedback histórico del analista para situaciones similares.

En MVP: modelo con features sintéticas que demuestra el pipeline.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np


@dataclass
class HypothesisCandidate:
    """Una hipótesis generada por Hermes lista para ranking."""
    id: str
    text: str
    features: np.ndarray   # vector de características numéricas
    ttp_tags: list[str] = None
    timestamp_score: float = 1.0   # relevancia temporal (0-1)
    playbook_success_rate: float = 0.5

    def __post_init__(self):
        if self.ttp_tags is None:
            self.ttp_tags = []


@dataclass
class RankedHypothesis:
    candidate: HypothesisCandidate
    stage1_score: float
    final_score: float = 0.0
    rank: int = 0


class AcmeStage1:
    """
    Ranker LightGBM de Stage 1.

    En MVP usa un modelo stub basado en features directas.
    La interfaz es idéntica a la versión con LightGBM real
    para facilitar el reemplazo.
    """

    def __init__(self) -> None:
        self._model = None
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Entrena el ranker con pares (features, score).

        En MVP usa regresión lineal como proxy de LightGBM.
        """
        try:
            import lightgbm as lgb
            self._model = lgb.LGBMRegressor(
                n_estimators=50,
                learning_rate=0.1,
                num_leaves=15,
                random_state=42,
                verbose=-1,
            )
            self._model.fit(X, y)
        except Exception:
            # fallback: media ponderada de features
            self._model = None
        self._fitted = True

    def score(self, features: np.ndarray) -> float:
        """Devuelve un score de relevancia en [0, 1]."""
        if not self._fitted:
            raise RuntimeError("AcmeStage1 no entrenado. Llama a fit() primero.")

        x = np.asarray(features, dtype=float).reshape(1, -1)

        if self._model is not None:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                raw = float(self._model.predict(x)[0])
        else:
            # fallback determinista: media de features normalizadas
            raw = float(np.clip(np.mean(x), 0.0, 1.0))

        return float(np.clip(raw, 0.0, 1.0))

    def rank(self, candidates: list[HypothesisCandidate]) -> list[RankedHypothesis]:
        """Ordena una lista de hipótesis por relevancia contextual."""
        if not candidates:
            return []

        ranked = []
        for candidate in candidates:
            # features: vector de la hipótesis + timestamp_score + playbook_success_rate
            features = np.concatenate([
                candidate.features,
                [candidate.timestamp_score, candidate.playbook_success_rate],
            ])
            stage1_score = self.score(features) if self._fitted else 0.5
            ranked.append(RankedHypothesis(
                candidate=candidate,
                stage1_score=stage1_score,
                final_score=stage1_score,
            ))

        ranked.sort(key=lambda r: r.stage1_score, reverse=True)
        for i, r in enumerate(ranked):
            r.rank = i + 1
        return ranked

    def save(self, path: Path | str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"model": self._model, "fitted": self._fitted}, f)

    @classmethod
    def load(cls, path: Path | str) -> "AcmeStage1":
        with open(path, "rb") as f:
            state = pickle.load(f)
        ranker = cls()
        ranker._model  = state["model"]
        ranker._fitted = state["fitted"]
        return ranker

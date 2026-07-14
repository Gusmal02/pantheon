"""
Acme Ranker — pipeline completo de ranking de hipótesis.

Stage 1 (LightGBM) → Stage 2 (IPCA por analista) → hipótesis ordenadas.

El feedback solo se incorpora al perfil IPCA si la firma JWT es válida.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pantheon.acme.feedback_auth import SignedFeedback, verify_feedback
from pantheon.acme.ipca import FeedbackVector, OperatorProfile, OutlierFeedback
from pantheon.acme.stage1 import AcmeStage1, HypothesisCandidate, RankedHypothesis
from pantheon.core.config import settings


class FeedbackRejected(ValueError):
    """Feedback rechazado por firma inválida o outlier no confirmado."""


@dataclass
class RankerResult:
    ranked: list[RankedHypothesis]
    operator_id: str
    stage2_applied: bool


class AcmeRanker:
    """
    Pipeline completo Acme Ranker.

    Uso:
        ranker = AcmeRanker(stage1, operator_profiles)
        result = ranker.rank(candidates, operator_id="op_1")
        ranker.accept_feedback(signed_feedback, jwt_secret="...")
    """

    def __init__(
        self,
        stage1: Optional[AcmeStage1] = None,
        operator_profiles: Optional[dict[str, OperatorProfile]] = None,
        jwt_secret: Optional[str] = None,
    ) -> None:
        self._stage1   = stage1 or AcmeStage1()
        self._profiles = operator_profiles or {}
        self._jwt_secret = jwt_secret or settings.pantheon_jwt_secret

    def rank(
        self,
        candidates: list[HypothesisCandidate],
        operator_id: str,
    ) -> RankerResult:
        """
        Ordena hipótesis con Stage 1 + Stage 2 para el operador indicado.
        Si el operador no tiene perfil calibrado, Stage 2 es neutral.
        """
        # Stage 1
        ranked = self._stage1.rank(candidates) if self._stage1._fitted else [
            RankedHypothesis(candidate=c, stage1_score=0.5, final_score=0.5, rank=i + 1)
            for i, c in enumerate(candidates)
        ]

        # Stage 2: ajuste IPCA por analista
        profile = self._profiles.get(operator_id)
        stage2_applied = False
        if profile and profile.is_calibrated:
            stage2_applied = True
            import numpy as np
            for r in ranked:
                ipca_score = profile.score_hypothesis(r.candidate.features)
                r.final_score = 0.6 * r.stage1_score + 0.4 * ipca_score

            ranked.sort(key=lambda r: r.final_score, reverse=True)
            for i, r in enumerate(ranked):
                r.rank = i + 1

        return RankerResult(
            ranked=ranked,
            operator_id=operator_id,
            stage2_applied=stage2_applied,
        )

    def accept_feedback(
        self,
        signed: SignedFeedback,
        force: bool = False,
    ) -> None:
        """
        Incorpora feedback al perfil IPCA del operador.

        Verifica la firma JWT antes de actualizar. Si la firma es inválida
        o el feedback es un outlier no confirmado → FeedbackRejected.

        Args:
            signed — feedback con firma JWT
            force  — omitir comprobación de outlier (solo para tests controlados)

        Raises:
            FeedbackRejected si la firma no es válida o hay outlier sin confirmar.
        """
        if not verify_feedback(signed, self._jwt_secret):
            raise FeedbackRejected(
                f"Firma de feedback inválida para operador {signed.operator_id}"
            )

        profile = self._profiles.setdefault(
            signed.operator_id,
            OperatorProfile(operator_id=signed.operator_id),
        )
        try:
            vec = FeedbackVector.from_dict(signed.payload)
            profile.update(vec, force=force)
        except OutlierFeedback as exc:
            raise FeedbackRejected(str(exc)) from exc

    def get_or_create_profile(self, operator_id: str) -> OperatorProfile:
        """Devuelve el perfil del operador, creándolo si no existe."""
        if operator_id not in self._profiles:
            self._profiles[operator_id] = OperatorProfile(operator_id=operator_id)
        return self._profiles[operator_id]

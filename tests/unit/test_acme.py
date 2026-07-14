"""Tests unitarios para Acme Ranker (feedback auth, IPCA, Stage1, pipeline)."""

import numpy as np
import pytest

from pantheon.acme.feedback_auth import (
    AuthError,
    SignedFeedback,
    create_operator_token,
    decode_operator_token,
    sign_feedback,
    verify_feedback,
)
from pantheon.acme.ipca import FeedbackVector, OperatorProfile, OutlierFeedback
from pantheon.acme.ranker import AcmeRanker, FeedbackRejected, RankerResult
from pantheon.acme.stage1 import AcmeStage1, HypothesisCandidate, RankedHypothesis

_SECRET = "test-secret-" + "x" * 32


# ── feedback_auth ─────────────────────────────────────────────────────────────

class TestFeedbackAuth:
    def test_sign_and_verify(self):
        payload = {"thumbs": "up", "relevance": 4, "clarity": 3}
        signed = sign_feedback(payload, "op_1", _SECRET)
        assert verify_feedback(signed, _SECRET)

    def test_tampered_payload_fails(self):
        payload = {"thumbs": "up", "relevance": 4}
        signed = sign_feedback(payload, "op_1", _SECRET)
        signed.payload["relevance"] = 1   # tamper
        assert not verify_feedback(signed, _SECRET)

    def test_wrong_secret_fails(self):
        payload = {"thumbs": "down"}
        signed = sign_feedback(payload, "op_1", _SECRET)
        assert not verify_feedback(signed, "wrong-secret")

    def test_different_operator_fails(self):
        payload = {"thumbs": "up"}
        signed = sign_feedback(payload, "op_1", _SECRET)
        signed.operator_id = "op_2"   # tamper operator
        assert not verify_feedback(signed, _SECRET)

    def test_create_and_decode_token(self):
        token = create_operator_token("op_test", _SECRET, expire_hours=1)
        decoded = decode_operator_token(token, _SECRET)
        assert decoded.operator_id == "op_test"
        assert "feedback" in decoded.scope

    def test_expired_token_raises(self):
        token = create_operator_token("op_test", _SECRET, expire_hours=-1)
        with pytest.raises(AuthError, match="expirado"):
            decode_operator_token(token, _SECRET)

    def test_invalid_token_format_raises(self):
        with pytest.raises(AuthError):
            decode_operator_token("not.a.valid.token.at.all", _SECRET)

    def test_tampered_signature_raises(self):
        token = create_operator_token("op_test", _SECRET, expire_hours=1)
        parts = token.split(".")
        parts[2] = "invalidsig"
        with pytest.raises(AuthError, match="inválida"):
            decode_operator_token(".".join(parts), _SECRET)


# ── IPCA / OperatorProfile ────────────────────────────────────────────────────

class TestOperatorProfile:
    def _fb(self, thumbs: str = "up") -> FeedbackVector:
        return FeedbackVector(
            thumbs=1.0 if thumbs == "up" else 0.0,
            relevance=0.8, clarity=0.7,
            actionability=0.9, urgency=0.6,
        )

    def test_starts_uncalibrated(self):
        profile = OperatorProfile("op_1")
        assert not profile.is_calibrated
        assert profile.feedback_count == 0

    def test_calibrated_after_5_samples(self):
        profile = OperatorProfile("op_1")
        for _ in range(5):
            profile.update(self._fb(), force=True)
        assert profile.is_calibrated

    def test_score_returns_float_when_calibrated(self):
        profile = OperatorProfile("op_1", n_components=2)
        for _ in range(5):
            profile.update(self._fb(), force=True)
        score = profile.score_hypothesis(np.array([0.8, 0.7, 0.9, 0.6, 0.5]))
        assert 0.0 <= score <= 1.0

    def test_score_returns_half_when_uncalibrated(self):
        profile = OperatorProfile("op_1")
        score = profile.score_hypothesis(np.ones(5))
        assert score == 0.5

    def test_outlier_raises(self):
        profile = OperatorProfile("op_1", outlier_threshold=1.0)
        for _ in range(5):
            profile.update(FeedbackVector(1.0, 0.8, 0.8, 0.8, 0.8), force=True)
        # feedback muy diferente → outlier
        with pytest.raises(OutlierFeedback):
            profile.update(FeedbackVector(0.0, 0.0, 0.0, 0.0, 0.0))

    def test_force_ignores_outlier(self):
        profile = OperatorProfile("op_1", outlier_threshold=0.01)
        for _ in range(5):
            profile.update(FeedbackVector(1.0, 0.8, 0.8, 0.8, 0.8), force=True)
        # no debe lanzar excepción con force=True
        profile.update(FeedbackVector(0.0, 0.0, 0.0, 0.0, 0.0), force=True)
        assert profile.feedback_count == 6

    def test_serialize_deserialize(self):
        profile = OperatorProfile("op_1")
        for _ in range(5):
            profile.update(self._fb(), force=True)
        data = profile.serialize()
        restored = OperatorProfile.deserialize(data, "op_1")
        assert restored.is_calibrated
        assert restored.feedback_count == profile.feedback_count

    def test_session_sliders_affect_score(self):
        profile = OperatorProfile("op_1")
        for _ in range(5):
            profile.update(self._fb(), force=True)
        features = np.array([0.5, 0.5, 0.5, 0.5, 0.5])
        profile.session_aggressiveness = 1.0
        profile.session_caution = 0.0
        score_aggressive = profile.score_hypothesis(features)
        profile.session_aggressiveness = 0.0
        profile.session_caution = 1.0
        score_cautious = profile.score_hypothesis(features)
        # scores deben ser diferentes con sliders extremos
        assert score_aggressive != score_cautious


# ── AcmeStage1 ───────────────────────────────────────────────────────────────

class TestAcmeStage1:
    def _trained(self) -> AcmeStage1:
        ranker = AcmeStage1()
        rng = np.random.default_rng(42)
        X = rng.uniform(0, 1, (100, 7))
        y = rng.uniform(0, 1, 100)
        ranker.fit(X, y)
        return ranker

    def _candidates(self, n: int = 3) -> list[HypothesisCandidate]:
        rng = np.random.default_rng(0)
        return [
            HypothesisCandidate(
                id=f"h{i}",
                text=f"Hipótesis {i}",
                features=rng.uniform(0, 1, 5),
            )
            for i in range(n)
        ]

    def test_score_in_range(self):
        ranker = self._trained()
        score = ranker.score(np.ones(7))
        assert 0.0 <= score <= 1.0

    def test_rank_returns_sorted(self):
        ranker = self._trained()
        candidates = self._candidates(5)
        ranked = ranker.rank(candidates)
        scores = [r.stage1_score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rank_assigns_correct_ranks(self):
        ranker = self._trained()
        candidates = self._candidates(3)
        ranked = ranker.rank(candidates)
        ranks = [r.rank for r in ranked]
        assert ranks == [1, 2, 3]

    def test_rank_empty_list(self):
        ranker = self._trained()
        assert ranker.rank([]) == []

    def test_save_and_load(self, tmp_path):
        ranker = self._trained()
        path = tmp_path / "stage1.pkl"
        ranker.save(path)
        loaded = AcmeStage1.load(path)
        x = np.ones(7)
        assert abs(ranker.score(x) - loaded.score(x)) < 1e-9

    def test_score_without_fit_raises(self):
        with pytest.raises(RuntimeError):
            AcmeStage1().score(np.ones(5))


# ── AcmeRanker (pipeline completo) ────────────────────────────────────────────

class TestAcmeRanker:
    def _ranker(self) -> AcmeRanker:
        stage1 = AcmeStage1()
        rng = np.random.default_rng(42)
        stage1.fit(rng.uniform(0, 1, (50, 7)), rng.uniform(0, 1, 50))
        return AcmeRanker(stage1=stage1, jwt_secret=_SECRET)

    def _candidates(self, n: int = 3) -> list[HypothesisCandidate]:
        rng = np.random.default_rng(1)
        return [
            HypothesisCandidate(
                id=f"h{i}",
                text=f"Hipótesis {i}",
                features=rng.uniform(0, 1, 5),
            )
            for i in range(n)
        ]

    def test_rank_returns_result(self):
        ranker = self._ranker()
        result = ranker.rank(self._candidates(), operator_id="op_1")
        assert isinstance(result, RankerResult)
        assert len(result.ranked) == 3

    def test_accept_valid_feedback(self):
        ranker = self._ranker()
        payload = {"thumbs": "up", "relevance": 4, "clarity": 3,
                   "actionability": 5, "urgency": 2}
        signed = sign_feedback(payload, "op_1", _SECRET)
        ranker.accept_feedback(signed, force=True)
        profile = ranker.get_or_create_profile("op_1")
        assert profile.feedback_count == 1

    def test_invalid_signature_rejected(self):
        ranker = self._ranker()
        payload = {"thumbs": "up", "relevance": 4}
        signed = SignedFeedback(
            operator_id="op_evil",
            payload=payload,
            signature="fakesig",
        )
        with pytest.raises(FeedbackRejected):
            ranker.accept_feedback(signed)

    def test_stage2_applied_after_calibration(self):
        ranker = self._ranker()
        payload = {"thumbs": "up", "relevance": 4, "clarity": 4,
                   "actionability": 4, "urgency": 3}
        for _ in range(5):
            signed = sign_feedback(payload, "op_1", _SECRET)
            ranker.accept_feedback(signed, force=True)

        result = ranker.rank(self._candidates(), operator_id="op_1")
        assert result.stage2_applied is True

    def test_stage2_not_applied_without_profile(self):
        ranker = self._ranker()
        result = ranker.rank(self._candidates(), operator_id="new_operator")
        assert result.stage2_applied is False

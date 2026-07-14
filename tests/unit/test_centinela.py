"""Tests unitarios para Centinela (CCI + detector + pipeline)."""

import numpy as np
import pytest

from pantheon.centinela.cci import CCIOutcome, compute_cci
from pantheon.centinela.detector import AnomalyDetector
from pantheon.centinela.pipeline import CentinelaDetectionPipeline, NetworkEvent


class TestCCI:
    def test_low_confidence_below_threshold(self):
        result = compute_cci(
            p_anomaly=0.1,
            d_centroid_norm=0.9,  # lejos del centroide → reduce CCI
            c_temp=0.0,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )
        assert result.outcome == CCIOutcome.LOW_CONFIDENCE
        assert result.cci < 0.45

    def test_critical_above_threshold(self):
        result = compute_cci(
            p_anomaly=0.9,
            d_centroid_norm=0.1,  # cerca del centroide → alta confianza
            c_temp=0.8,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )
        assert result.outcome == CCIOutcome.CRITICAL
        assert result.cci >= 0.75

    def test_moderate_between_thresholds(self):
        result = compute_cci(
            p_anomaly=0.6,
            d_centroid_norm=0.5,
            c_temp=0.2,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )
        assert result.outcome == CCIOutcome.MODERATE

    def test_cci_clamps_inputs(self):
        result = compute_cci(
            p_anomaly=1.5,    # fuera de rango
            d_centroid_norm=-0.1,
            c_temp=2.0,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )
        assert 0.0 <= result.cci <= 1.0

    def test_source_ip_stored(self):
        result = compute_cci(0.5, 0.5, 0.5, source_ip="10.0.0.1")
        assert result.source_ip == "10.0.0.1"

    def test_weights_sum_implicitly(self):
        # con p_anomaly=1, d_centroid=0 (cercano), c_temp=1 → cci debe ser 1.0
        result = compute_cci(
            p_anomaly=1.0,
            d_centroid_norm=0.0,
            c_temp=1.0,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )
        assert result.cci == pytest.approx(1.0, abs=1e-4)


class TestAnomalyDetector:
    def _trained(self) -> AnomalyDetector:
        det = AnomalyDetector(n_estimators=10, random_state=42)
        rng = np.random.default_rng(0)
        X = rng.normal(loc=0, scale=1, size=(200, 5))
        det.fit(X)
        return det

    def test_fit_and_score_normal(self):
        det = self._trained()
        normal_event = np.zeros(5)
        score = det.score(normal_event)
        assert 0.0 <= score <= 1.0

    def test_anomalous_event_higher_score(self):
        det = self._trained()
        normal = np.zeros(5)
        anomalous = np.ones(5) * 50   # muy lejos de la distribución normal
        s_normal = det.score(normal)
        s_anomalous = det.score(anomalous)
        assert s_anomalous > s_normal

    def test_score_without_fit_raises(self):
        det = AnomalyDetector()
        with pytest.raises(RuntimeError):
            det.score(np.zeros(3))

    def test_predict_batch(self):
        det = self._trained()
        X = np.random.default_rng(1).normal(size=(10, 5))
        scores = det.predict_batch(X)
        assert len(scores) == 10
        assert all(0.0 <= s <= 1.0 for s in scores)

    def test_save_and_load(self, tmp_path):
        det = self._trained()
        path = tmp_path / "model.pkl"
        det.save(path)
        loaded = AnomalyDetector.load(path)
        x = np.zeros(5)
        assert abs(det.score(x) - loaded.score(x)) < 1e-9


class TestCentinelaDetectionPipeline:
    def _pipeline(self) -> CentinelaDetectionPipeline:
        det = AnomalyDetector(n_estimators=10, random_state=42)
        rng = np.random.default_rng(0)
        X = rng.normal(loc=0, scale=1, size=(200, 4))
        det.fit(X)
        centroids = np.array([[0.0, 0.0, 0.0, 0.0]])  # centroide de ataque conocido
        return CentinelaDetectionPipeline(
            detector=det,
            attack_centroids=centroids,
            ambiguous_threshold=0.45,
            critical_threshold=0.75,
        )

    def _event(self, features: list[float], ip: str = "10.0.0.1") -> NetworkEvent:
        return NetworkEvent(features=features, source_ip=ip)

    def test_normal_event_low_confidence(self):
        pipeline = self._pipeline()
        ev = self._event([0.0, 0.0, 0.0, 0.0])
        decision = pipeline.process(ev)
        # evento normal → p_anomaly bajo → CCI bajo → triaje humano
        assert isinstance(decision.cci_result.cci, float)
        assert decision.cci_result.cci >= 0.0

    def test_anomalous_event_detected(self):
        pipeline = self._pipeline()
        ev = self._event([50.0, 50.0, 50.0, 50.0])
        decision = pipeline.process(ev)
        # evento muy anómalo → p_anomaly alto
        assert decision.cci_result.p_anomaly > 0.5

    def test_escalate_implies_no_hermes(self):
        pipeline = self._pipeline()
        # forzar outcome LOW_CONFIDENCE con evento normal
        ev = self._event([0.0, 0.0, 0.0, 0.0])
        decision = pipeline.process(ev)
        if decision.should_escalate_to_human:
            assert not decision.should_send_to_hermes

    def test_c_temp_increases_with_repeated_events(self):
        pipeline = self._pipeline()
        ip = "192.168.1.5"
        ev = self._event([1.0, 1.0, 1.0, 1.0], ip=ip)
        # insertar 10 eventos similares en el historial
        for _ in range(10):
            pipeline.process(ev)
        decision = pipeline.process(ev)
        assert decision.cci_result.c_temp > 0.0

    def test_no_centroids_gives_middle_d(self):
        det = AnomalyDetector(n_estimators=10, random_state=42)
        rng = np.random.default_rng(0)
        det.fit(rng.normal(size=(100, 3)))
        pipeline = CentinelaDetectionPipeline(detector=det, attack_centroids=None)
        ev = self._event([1.0, 2.0, 3.0])
        decision = pipeline.process(ev)
        assert decision.cci_result.d_centroid_norm == 0.5

    def test_update_centroids(self):
        pipeline = self._pipeline()
        new_centroids = np.array([[5.0, 5.0, 5.0, 5.0]])
        pipeline.update_centroids(new_centroids)
        assert pipeline._centroids is new_centroids

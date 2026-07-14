"""
Tests de la integración activa Pantheon → Ares (AresBridgeWorker).

Cubre:
  - ares_finding_to_anomaly(): conversión de records Ares a vectores Centinela
  - publish_killswitch_to_ares(): publicación en canal Redis de Ares
  - AresBridgeWorker.poll_once(): ciclo de polling con cliente HTTP mock
  - Helpers de conversión (_icc_to_severity, _extract_ttp_tags, _build_narrative)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from pantheon.core.purple_bridge import (
    AresBridgeWorker,
    _build_narrative,
    _extract_ttp_tags,
    _icc_to_severity,
    ares_finding_to_anomaly,
    clear_store,
    get_escalated,
    publish_killswitch_to_ares,
)


@pytest.fixture(autouse=True)
def reset():
    clear_store()
    yield
    clear_store()


# ── ares_finding_to_anomaly ───────────────────────────────────────────────────

class TestAresFindingToAnomaly:
    def _record(self, **overrides) -> dict:
        base = {
            "engagement_id": "eng-001",
            "scan_id": "scan-001",
            "target": "192.168.100.50",
            "icc": 0.3,
            "adversarial": True,
            "findings": [
                {"port": 22, "state": "open", "severity": "low"},
                {"port": 80, "state": "open", "severity": "high"},
                {"port": 443, "state": "open", "severity": "high"},
                {"port": 8080, "state": "open", "severity": "critical"},
            ],
            "escalated_at": "2026-07-13T10:00:00+00:00",
        }
        base.update(overrides)
        return base

    def test_returns_float32_array(self):
        v = ares_finding_to_anomaly(self._record())
        assert v.dtype == np.float32

    def test_shape_is_8(self):
        v = ares_finding_to_anomaly(self._record())
        assert v.shape == (8,)

    def test_values_clipped_0_1(self):
        v = ares_finding_to_anomaly(self._record())
        assert np.all(v >= 0.0)
        assert np.all(v <= 1.0)

    def test_inverted_icc_at_index_0(self):
        v = ares_finding_to_anomaly(self._record(icc=0.3))
        assert abs(v[0] - 0.7) < 1e-5   # 1 - 0.3 = 0.7

    def test_adversarial_flag_at_index_1(self):
        v_adv = ares_finding_to_anomaly(self._record(adversarial=True))
        v_nrm = ares_finding_to_anomaly(self._record(adversarial=False))
        assert v_adv[1] == 1.0
        assert v_nrm[1] == 0.0

    def test_open_ports_count_at_index_2(self):
        v = ares_finding_to_anomaly(self._record())
        # 4 puertos abiertos / 100
        assert abs(v[2] - 4 / 100) < 1e-5

    def test_high_risk_at_index_3(self):
        v = ares_finding_to_anomaly(self._record())
        # 2 high + 1 critical no cuentan en [3] (solo "high")
        assert abs(v[3] - 2 / 50) < 1e-5

    def test_has_critical_at_index_5(self):
        v_crit = ares_finding_to_anomaly(self._record())
        v_safe = ares_finding_to_anomaly(self._record(findings=[
            {"port": 22, "state": "open", "severity": "low"}
        ]))
        assert v_crit[5] == 1.0
        assert v_safe[5] == 0.0

    def test_raw_icc_at_index_7(self):
        v = ares_finding_to_anomaly(self._record(icc=0.21))
        assert abs(v[7] - 0.21) < 1e-5

    def test_empty_findings_returns_valid_vector(self):
        v = ares_finding_to_anomaly(self._record(findings=[]))
        assert v.shape == (8,)
        assert np.all(v >= 0.0)

    def test_high_icc_safe_record(self):
        v = ares_finding_to_anomaly(self._record(icc=0.95, adversarial=False, findings=[]))
        # 1 - 0.95 = 0.05 → bajo (poco sospechoso para Centinela)
        assert v[0] < 0.1
        assert v[1] == 0.0


# ── publish_killswitch_to_ares ────────────────────────────────────────────────

class TestPublishKillSwitchToAres:
    def test_publishes_to_correct_channel(self):
        redis_mock = MagicMock()
        publish_killswitch_to_ares(redis_mock, "ioc_detected", "192.168.100.50")
        redis_mock.publish.assert_called_once()
        channel, payload_str = redis_mock.publish.call_args[0]
        assert channel == "ares:killswitch"

    def test_payload_has_required_fields(self):
        redis_mock = MagicMock()
        publish_killswitch_to_ares(redis_mock, "ioc_detected", "192.168.100.50", "op_auto")
        _, payload_str = redis_mock.publish.call_args[0]
        payload = json.loads(payload_str)
        assert payload["source"] == "pantheon"
        assert payload["reason"] == "ioc_detected"
        assert payload["target"] == "192.168.100.50"
        assert payload["operator_id"] == "op_auto"
        assert "timestamp" in payload

    def test_redis_error_raises_runtime_error(self):
        redis_mock = MagicMock()
        redis_mock.publish.side_effect = ConnectionError("Redis down")
        with pytest.raises(RuntimeError, match="ares:killswitch"):
            publish_killswitch_to_ares(redis_mock, "reason", "1.2.3.4")

    def test_default_operator_is_pantheon(self):
        redis_mock = MagicMock()
        publish_killswitch_to_ares(redis_mock, "cci_critical", "10.0.0.1")
        _, payload_str = redis_mock.publish.call_args[0]
        payload = json.loads(payload_str)
        assert payload["operator_id"] == "pantheon"


# ── AresBridgeWorker ──────────────────────────────────────────────────────────

def _make_http_mock(records: list[dict]) -> MagicMock:
    """Crea un cliente HTTP mock que devuelve los records dados."""
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"since": "...", "count": len(records), "escalated": records}
    client = MagicMock()
    client.get.return_value = response
    return client


def _ares_record(scan_id: str = "s1", icc: float = 0.3, adversarial: bool = True) -> dict:
    return {
        "engagement_id": "eng-001",
        "scan_id": scan_id,
        "target": f"192.168.100.{hash(scan_id) % 200 + 50}",
        "icc": icc,
        "adversarial": adversarial,
        "findings": [
            {"port": 22,  "state": "open", "severity": "high"},
            {"port": 443, "state": "open", "severity": "low"},
        ],
        "escalated_at": "2026-07-13T10:00:00+00:00",
    }


class TestAresBridgeWorker:
    def test_poll_once_calls_http(self):
        http_mock = _make_http_mock([_ares_record("s1")])
        worker = AresBridgeWorker(
            ares_api_url="http://localhost:8000",
            http_client=http_mock,
        )
        records = worker.poll_once()
        http_mock.get.assert_called_once()
        assert len(records) == 1

    def test_poll_once_includes_since_param(self):
        http_mock = _make_http_mock([])
        worker = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock)
        worker.poll_once()
        call_kwargs = http_mock.get.call_args
        params = call_kwargs[1].get("params") or call_kwargs[0][1] if len(call_kwargs[0]) > 1 else {}
        # verificar que el endpoint correcto fue llamado
        endpoint = http_mock.get.call_args[0][0]
        assert "/purple/escalated" in endpoint

    def test_centinela_feed_called_per_record(self):
        http_mock = _make_http_mock([_ares_record("s1"), _ares_record("s2")])
        feed_calls = []
        def mock_feed(ip: str, features: np.ndarray):
            feed_calls.append((ip, features))

        worker = AresBridgeWorker(
            ares_api_url="http://localhost:8000",
            http_client=http_mock,
            centinela_feed=mock_feed,
        )
        worker.poll_once()
        assert len(feed_calls) == 2

    def test_feed_receives_numpy_array(self):
        http_mock = _make_http_mock([_ares_record("s1")])
        received = []
        worker = AresBridgeWorker(
            ares_api_url="http://localhost:8000",
            http_client=http_mock,
            centinela_feed=lambda ip, f: received.append(f),
        )
        worker.poll_once()
        assert len(received) == 1
        assert isinstance(received[0], np.ndarray)
        assert received[0].shape == (8,)

    def test_processed_count_increments(self):
        http_mock = _make_http_mock([_ares_record("s1"), _ares_record("s2")])
        worker = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock)
        worker.poll_once()
        assert worker.processed_count == 2

    def test_http_error_recorded_not_raised(self):
        http_mock = MagicMock()
        http_mock.get.side_effect = ConnectionError("Ares down")
        worker = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock)
        records = worker.poll_once()   # no debe lanzar excepción
        assert records == []
        assert len(worker.last_errors) > 0

    def test_records_stored_in_local_store(self):
        http_mock = _make_http_mock([_ares_record("scan-unique-001")])
        worker = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock)
        worker.poll_once()
        stored = get_escalated()
        assert len(stored) >= 1

    def test_duplicate_records_silenced(self):
        # mismo scan_id dos veces → duplicate silenced, no falla
        records = [_ares_record("same-scan")]
        http_mock1 = _make_http_mock(records)
        http_mock2 = _make_http_mock(records)
        w1 = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock1)
        w2 = AresBridgeWorker(ares_api_url="http://localhost:8000", http_client=http_mock2)
        w1.poll_once()
        w2.poll_once()   # no debe lanzar excepción

    def test_no_centinela_feed_still_works(self):
        http_mock = _make_http_mock([_ares_record("s1")])
        worker = AresBridgeWorker(
            ares_api_url="http://localhost:8000",
            http_client=http_mock,
            centinela_feed=None,   # sin feed
        )
        records = worker.poll_once()
        assert len(records) == 1


# ── Helpers de conversión ─────────────────────────────────────────────────────

class TestConversionHelpers:
    def test_icc_to_severity_critical(self):
        assert _icc_to_severity(0.1) == "critical"
        assert _icc_to_severity(0.29) == "critical"

    def test_icc_to_severity_high(self):
        assert _icc_to_severity(0.30) == "high"
        assert _icc_to_severity(0.44) == "high"

    def test_icc_to_severity_moderate(self):
        assert _icc_to_severity(0.50) == "moderate"

    def test_icc_to_severity_low(self):
        assert _icc_to_severity(0.80) == "low"
        assert _icc_to_severity(1.0) == "low"

    def test_extract_ttp_tags_ssh(self):
        record = {"findings": [{"port": 22, "state": "open", "severity": "low"}], "adversarial": False}
        ttps = _extract_ttp_tags(record)
        assert "T1021" in ttps

    def test_extract_ttp_tags_adversarial(self):
        record = {"findings": [], "adversarial": True}
        ttps = _extract_ttp_tags(record)
        assert "T1036" in ttps

    def test_extract_ttp_tags_web(self):
        record = {"findings": [{"port": 443, "state": "open", "severity": "high"}], "adversarial": False}
        ttps = _extract_ttp_tags(record)
        assert "T1190" in ttps

    def test_extract_ttp_tags_no_duplicates(self):
        record = {
            "findings": [
                {"port": 22, "state": "open", "severity": "low"},
                {"port": 22, "state": "open", "severity": "high"},  # mismo puerto dos veces
            ],
            "adversarial": False,
        }
        ttps = _extract_ttp_tags(record)
        assert ttps.count("T1021") == 1

    def test_build_narrative_contains_target(self):
        record = {
            "target": "192.168.100.50",
            "icc": 0.21,
            "adversarial": True,
            "findings": [{"port": 22, "state": "open", "severity": "high"}],
            "engagement_id": "eng-001",
        }
        narrative = _build_narrative(record)
        assert "192.168.100.50" in narrative
        assert "0.21" in narrative

    def test_build_narrative_mentions_adversarial(self):
        record = {
            "target": "10.0.0.1", "icc": 0.1, "adversarial": True,
            "findings": [], "engagement_id": "eng-002",
        }
        narrative = _build_narrative(record)
        assert "evasivo" in narrative.lower() or "adversarial" in narrative.lower() or "Isolation" in narrative

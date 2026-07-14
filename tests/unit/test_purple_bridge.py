"""
Tests unitarios del Purple Team Bridge.

Cubre validación Pydantic, detección de duplicados, allowlist de hosts,
y los endpoints GET/POST /purple/escalated de la API.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pantheon.acme.feedback_auth import create_operator_token
from pantheon.api.main import app
from pantheon.core.config import settings
from pantheon.core.purple_bridge import (
    EscalatedHypothesis,
    PurpleBridgeError,
    clear_store,
    get_escalated,
    mark_processed,
    receive_escalated,
)

_SECRET = settings.pantheon_jwt_secret
_client = TestClient(app)


def _auth() -> dict:
    token = create_operator_token("op_purple", _SECRET, expire_hours=1)
    return {"Authorization": f"Bearer {token}"}


def _valid_payload(**overrides) -> dict:
    base = {
        "hypothesis_id": "hyp-purple-001",
        "source_ip": "192.168.100.50",
        "ttp_tags": ["T1003", "T1021"],
        "severity": "high",
        "narrative": "Lateral movement detected from purple team exercise targeting credential store",
        "ares_source": "localhost",
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def reset_store():
    """Limpia el store entre tests para evitar contaminación."""
    clear_store()
    yield
    clear_store()


# ── EscalatedHypothesis Pydantic validation ───────────────────────────────────

class TestEscalatedHypothesisValidation:
    def test_valid_payload_accepted(self):
        h = EscalatedHypothesis(**_valid_payload())
        assert h.hypothesis_id == "hyp-purple-001"

    def test_invalid_hypothesis_id_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(hypothesis_id="bad id with spaces!"))

    def test_invalid_source_ip_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(source_ip="not-an-ip"))

    def test_invalid_severity_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(severity="extreme"))

    def test_unauthorized_ares_source_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(ares_source="evil.attacker.com"))

    def test_empty_narrative_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(narrative=""))

    def test_too_long_narrative_rejected(self):
        with pytest.raises(Exception):
            EscalatedHypothesis(**_valid_payload(narrative="x" * 2001))

    def test_severity_normalized_lowercase(self):
        h = EscalatedHypothesis(**_valid_payload(severity="HIGH"))
        assert h.severity == "high"

    def test_ares_source_with_port_accepted(self):
        h = EscalatedHypothesis(**_valid_payload(ares_source="localhost:8000"))
        assert h.ares_source == "localhost:8000"

    def test_all_valid_severities_accepted(self):
        for sev in ["low", "moderate", "high", "critical"]:
            h = EscalatedHypothesis(**_valid_payload(severity=sev))
            assert h.severity == sev


# ── receive_escalated ─────────────────────────────────────────────────────────

class TestReceiveEscalated:
    def test_valid_payload_stored(self):
        record = receive_escalated(_valid_payload())
        assert record.hypothesis.hypothesis_id == "hyp-purple-001"
        stored = get_escalated()
        assert len(stored) == 1

    def test_content_hash_computed(self):
        record = receive_escalated(_valid_payload())
        assert len(record.content_hash) == 64   # SHA-256 hex

    def test_duplicate_rejected(self):
        receive_escalated(_valid_payload())
        with pytest.raises(PurpleBridgeError, match="duplicado"):
            receive_escalated(_valid_payload())

    def test_different_payload_accepted(self):
        receive_escalated(_valid_payload(hypothesis_id="hyp-001"))
        receive_escalated(_valid_payload(hypothesis_id="hyp-002"))
        assert len(get_escalated()) == 2

    def test_invalid_payload_raises_bridge_error(self):
        with pytest.raises(PurpleBridgeError):
            receive_escalated({"hypothesis_id": "bad id!", "source_ip": "x"})


# ── get_escalated ─────────────────────────────────────────────────────────────

class TestGetEscalated:
    def test_empty_store_returns_empty(self):
        assert get_escalated() == []

    def test_limit_respected(self):
        for i in range(5):
            receive_escalated(_valid_payload(
                hypothesis_id=f"hyp-{i:03d}",
                narrative=f"Narrative for escalation {i} from purple team exercise",
            ))
        result = get_escalated(limit=3)
        assert len(result) == 3

    def test_only_unprocessed_filter(self):
        receive_escalated(_valid_payload(hypothesis_id="hyp-A"))
        receive_escalated(_valid_payload(
            hypothesis_id="hyp-B",
            narrative="Second escalation from purple team lateral movement exercise",
        ))
        r = get_escalated()
        mark_processed(r[0]["content_hash"])
        unprocessed = get_escalated(only_unprocessed=True)
        assert len(unprocessed) == 1
        assert unprocessed[0]["hypothesis_id"] == "hyp-B"


# ── mark_processed ────────────────────────────────────────────────────────────

class TestMarkProcessed:
    def test_marks_existing_record(self):
        record = receive_escalated(_valid_payload())
        result = mark_processed(record.content_hash)
        assert result is True
        stored = get_escalated(only_unprocessed=True)
        assert len(stored) == 0

    def test_unknown_hash_returns_false(self):
        result = mark_processed("0" * 64)
        assert result is False


# ── Endpoints API /purple/escalated ──────────────────────────────────────────

class TestPurpleAPIEndpoints:
    def test_get_escalated_requires_auth(self):
        r = _client.get("/purple/escalated")
        assert r.status_code == 422

    def test_get_escalated_empty(self):
        r = _client.get("/purple/escalated", headers=_auth())
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_post_escalated_valid(self):
        r = _client.post(
            "/purple/escalated",
            json=_valid_payload(),
            headers=_auth(),
        )
        assert r.status_code == 201
        assert r.json()["accepted"] is True
        assert "content_hash" in r.json()

    def test_post_escalated_invalid_payload_422(self):
        r = _client.post(
            "/purple/escalated",
            json={"hypothesis_id": "INVALID ID WITH SPACES!!"},
            headers=_auth(),
        )
        assert r.status_code == 422

    def test_post_then_get_returns_record(self):
        _client.post("/purple/escalated", json=_valid_payload(), headers=_auth())
        r = _client.get("/purple/escalated", headers=_auth())
        assert r.json()["count"] == 1
        assert r.json()["escalated"][0]["hypothesis_id"] == "hyp-purple-001"

    def test_post_duplicate_422(self):
        _client.post("/purple/escalated", json=_valid_payload(), headers=_auth())
        r = _client.post("/purple/escalated", json=_valid_payload(), headers=_auth())
        assert r.status_code == 422

    def test_post_unauthorized_ares_source_422(self):
        r = _client.post(
            "/purple/escalated",
            json=_valid_payload(ares_source="malicious.attacker.io"),
            headers=_auth(),
        )
        assert r.status_code == 422

    def test_get_limit_param(self):
        for i in range(5):
            _client.post(
                "/purple/escalated",
                json=_valid_payload(
                    hypothesis_id=f"hyp-{i:03d}",
                    narrative=f"Exercise {i} narrative from purple team lateral movement",
                ),
                headers=_auth(),
            )
        r = _client.get("/purple/escalated?limit=2", headers=_auth())
        assert r.json()["count"] == 2

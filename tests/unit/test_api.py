"""Tests unitarios para la API FastAPI de Pantheon."""

import pytest
from fastapi.testclient import TestClient

from pantheon.acme.feedback_auth import create_operator_token, sign_feedback
from pantheon.api.main import app
from pantheon.core.config import settings

_SECRET = settings.pantheon_jwt_secret
_client = TestClient(app)


def _token(operator_id: str = "op_test") -> str:
    return create_operator_token(operator_id, _SECRET, expire_hours=1)


def _auth_header(operator_id: str = "op_test") -> dict:
    return {"Authorization": f"Bearer {_token(operator_id)}"}


class TestHealth:
    def test_health_ok(self):
        r = _client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_no_auth_required(self):
        r = _client.get("/health")
        assert r.status_code == 200


class TestAuth:
    def test_missing_auth_header_returns_422(self):
        r = _client.get("/hypotheses")
        assert r.status_code == 422

    def test_invalid_token_returns_401(self):
        r = _client.get("/hypotheses", headers={"Authorization": "Bearer invalid.tok.en"})
        assert r.status_code == 401

    def test_valid_token_accepted(self):
        r = _client.get("/hypotheses", headers=_auth_header())
        assert r.status_code == 200


class TestEvents:
    def test_post_event_accepted(self):
        payload = {"features": [0.1, 0.2, 0.3], "source_ip": "10.0.0.1"}
        r = _client.post("/events", json=payload, headers=_auth_header())
        assert r.status_code == 202
        assert r.json()["accepted"] is True

    def test_post_event_no_auth_returns_422(self):
        r = _client.post("/events", json={"features": [0.1], "source_ip": "10.0.0.1"})
        assert r.status_code == 422


class TestApprovalEndpoints:
    def test_approve_returns_approved(self):
        r = _client.post("/approve/req-123", headers=_auth_header())
        assert r.status_code == 200
        assert r.json()["status"] == "approved"

    def test_deny_returns_denied(self):
        r = _client.post("/deny/req-456", headers=_auth_header())
        assert r.status_code == 200
        assert r.json()["status"] == "denied"

    def test_pending_returns_list(self):
        r = _client.get("/pending", headers=_auth_header())
        assert r.status_code == 200
        assert "pending" in r.json()


class TestFeedback:
    def test_valid_feedback_accepted(self):
        payload = {
            "thumbs": "up", "relevance": 4,
            "clarity": 4, "actionability": 5, "urgency": 3,
        }
        signed = sign_feedback(payload, "op_test", _SECRET)
        r = _client.post(
            "/feedback",
            json={
                "hypothesis_id": "h1",
                "thumbs": "up",
                "relevance": 4,
                "clarity": 4,
                "actionability": 5,
                "urgency": 3,
                "signature": signed.signature,
            },
            headers=_auth_header("op_test"),
        )
        assert r.status_code == 200
        assert r.json()["accepted"] is True

    def test_invalid_signature_rejected(self):
        r = _client.post(
            "/feedback",
            json={
                "hypothesis_id": "h1",
                "thumbs": "up",
                "relevance": 4,
                "clarity": 4,
                "actionability": 5,
                "urgency": 3,
                "signature": "invalidsignature",
            },
            headers=_auth_header("op_test"),
        )
        assert r.status_code == 403


class TestAudit:
    def test_audit_returns_list(self):
        r = _client.get("/audit", headers=_auth_header())
        assert r.status_code == 200
        assert "entries" in r.json()


class TestKillSwitch:
    def test_killswitch_triggered(self):
        r = _client.post(
            "/killswitch",
            json={"reason": "test trigger"},
            headers=_auth_header(),
        )
        assert r.status_code == 200
        assert r.json()["triggered"] is True
        assert r.json()["reason"] == "test trigger"

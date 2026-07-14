"""
Tests unitarios del War Room.

Se testea la lógica de negocio (authenticate, verify_token, build_feedback_payload,
sign_operator_feedback, trigger_killswitch, AdaptiveWatchdog) en aislamiento,
sin levantar la UI de Gradio.
"""

from __future__ import annotations

import time

import pytest

from pantheon.acme.feedback_auth import verify_feedback
from pantheon.war_room.app import (
    AdaptiveWatchdog,
    SessionState,
    authenticate,
    build_feedback_payload,
    sign_operator_feedback,
    trigger_killswitch,
    verify_token,
)

_SECRET = "war-room-test-secret-" + "x" * 32


# ── Autenticación ─────────────────────────────────────────────────────────────

class TestAuthenticate:
    def test_valid_operator_returns_token(self):
        ok, token, msg = authenticate("op_test", _SECRET)
        assert ok is True
        assert len(token) > 0

    def test_empty_operator_fails(self):
        ok, token, msg = authenticate("", _SECRET)
        assert ok is False
        assert token == ""

    def test_whitespace_operator_fails(self):
        ok, token, msg = authenticate("   ", _SECRET)
        assert ok is False

    def test_message_contains_operator_id(self):
        ok, _, msg = authenticate("op_garcia", _SECRET)
        assert "op_garcia" in msg

    def test_generated_token_is_verifiable(self):
        ok, token, _ = authenticate("op_001", _SECRET)
        valid, op_id = verify_token(token, _SECRET)
        assert valid is True
        assert op_id == "op_001"


class TestVerifyToken:
    def test_valid_token_passes(self):
        _, token, _ = authenticate("op_test", _SECRET)
        valid, op_id = verify_token(token, _SECRET)
        assert valid is True
        assert op_id == "op_test"

    def test_invalid_token_fails(self):
        valid, msg = verify_token("not.a.real.token", _SECRET)
        assert valid is False

    def test_wrong_secret_fails(self):
        _, token, _ = authenticate("op_test", _SECRET)
        valid, _ = verify_token(token, "wrong-secret-" + "x" * 32)
        assert valid is False

    def test_expired_token_fails(self):
        from pantheon.acme.feedback_auth import create_operator_token
        expired = create_operator_token("op_test", _SECRET, expire_hours=-1)
        valid, msg = verify_token(expired, _SECRET)
        assert valid is False


# ── Feedback dimensional ──────────────────────────────────────────────────────

class TestBuildFeedbackPayload:
    def test_all_fields_present(self):
        p = build_feedback_payload("hyp-1", "up", 4, 3, 5, 2)
        assert p["hypothesis_id"] == "hyp-1"
        assert p["thumbs"] == "up"
        assert p["relevance"] == 4
        assert p["clarity"] == 3
        assert p["actionability"] == 5
        assert p["urgency"] == 2

    def test_thumbs_down(self):
        p = build_feedback_payload("h", "down", 1, 1, 1, 1)
        assert p["thumbs"] == "down"

    def test_numeric_values_preserved(self):
        p = build_feedback_payload("h", "up", 5, 5, 5, 5)
        for k in ["relevance", "clarity", "actionability", "urgency"]:
            assert isinstance(p[k], int)


class TestSignOperatorFeedback:
    def test_returns_signed_feedback(self):
        payload = build_feedback_payload("hyp-1", "up", 4, 3, 5, 2)
        signed = sign_operator_feedback(payload, "op_test", _SECRET)
        assert signed.operator_id == "op_test"
        assert len(signed.signature) == 64   # hex SHA-256

    def test_signature_is_verifiable(self):
        payload = build_feedback_payload("hyp-1", "up", 4, 3, 5, 2)
        signed = sign_operator_feedback(payload, "op_test", _SECRET)
        assert verify_feedback(signed, _SECRET) is True

    def test_different_operators_different_signatures(self):
        payload = build_feedback_payload("hyp-1", "up", 4, 3, 5, 2)
        s1 = sign_operator_feedback(payload, "op_A", _SECRET)
        s2 = sign_operator_feedback(payload, "op_B", _SECRET)
        assert s1.signature != s2.signature

    def test_tampered_payload_invalid(self):
        payload = build_feedback_payload("hyp-1", "up", 4, 3, 5, 2)
        signed = sign_operator_feedback(payload, "op_test", _SECRET)
        signed.payload["relevance"] = 99
        assert verify_feedback(signed, _SECRET) is False


# ── Kill Switch ───────────────────────────────────────────────────────────────

class TestTriggerKillSwitch:
    def test_returns_triggered_true(self):
        result = trigger_killswitch("op_test", "test reason")
        assert result["triggered"] is True

    def test_includes_operator_id(self):
        result = trigger_killswitch("op_garcia", "emergency")
        assert result["operator_id"] == "op_garcia"

    def test_includes_reason(self):
        result = trigger_killswitch("op_test", "false positive confirmed")
        assert "false positive confirmed" in result["reason"]

    def test_includes_timestamp(self):
        before = time.time()
        result = trigger_killswitch("op_test", "reason")
        after = time.time()
        assert before <= result["timestamp"] <= after


# ── Adaptive Watchdog ─────────────────────────────────────────────────────────

class TestAdaptiveWatchdog:
    def test_no_alert_initially(self):
        wd = AdaptiveWatchdog(timeout_secs=60, check_interval=1)
        state = SessionState(operator_id="op_1", authenticated=True)
        wd.register_session("op_1", state)
        assert wd.get_alert("op_1") == ""

    def test_alert_after_timeout(self):
        wd = AdaptiveWatchdog(timeout_secs=0, check_interval=1)
        state = SessionState(operator_id="op_1", authenticated=True)
        state.hypotheses = [{"id": "h1"}]   # hay hipótesis pendiente
        state.last_action_ts = time.time() - 5  # ya pasó el timeout
        wd.register_session("op_1", state)
        wd._run_once()  # ejecutar un ciclo manual
        assert wd.get_alert("op_1") != ""

    def test_touch_clears_alert(self):
        wd = AdaptiveWatchdog(timeout_secs=0, check_interval=1)
        state = SessionState(operator_id="op_2", authenticated=True)
        state.hypotheses = [{"id": "h1"}]
        state.last_action_ts = time.time() - 5
        wd.register_session("op_2", state)
        wd._run_once()
        assert wd.get_alert("op_2") != ""
        wd.touch("op_2")
        assert wd.get_alert("op_2") == ""

    def test_no_alert_without_hypotheses(self):
        wd = AdaptiveWatchdog(timeout_secs=0, check_interval=1)
        state = SessionState(operator_id="op_3", authenticated=True)
        state.hypotheses = []    # sin hipótesis → no hay razón para alertar
        state.last_action_ts = time.time() - 9999
        wd.register_session("op_3", state)
        wd._run_once()
        assert wd.get_alert("op_3") == ""

    def test_no_alert_after_killswitch(self):
        wd = AdaptiveWatchdog(timeout_secs=0, check_interval=1)
        state = SessionState(operator_id="op_4", authenticated=True)
        state.hypotheses = [{"id": "h1"}]
        state.last_action_ts = time.time() - 9999
        state.killswitch_triggered = True   # kill switch activado
        wd.register_session("op_4", state)
        wd._run_once()
        assert wd.get_alert("op_4") == ""

    def test_unknown_operator_empty_alert(self):
        wd = AdaptiveWatchdog(timeout_secs=0, check_interval=1)
        assert wd.get_alert("nonexistent") == ""


# ── SessionState ──────────────────────────────────────────────────────────────

class TestSessionState:
    def test_default_not_authenticated(self):
        s = SessionState()
        assert s.authenticated is False

    def test_default_empty_hypotheses(self):
        s = SessionState()
        assert s.hypotheses == []

    def test_killswitch_false_by_default(self):
        s = SessionState()
        assert s.killswitch_triggered is False

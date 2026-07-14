"""Tests unitarios para ApprovalGate (sin Redis real)."""

import json
import time
from unittest.mock import MagicMock

import pytest

from pantheon.core.approval import (
    ApprovalDenied,
    ApprovalGate,
    ApprovalRequest,
    ApprovalStatus,
)


def _mock_redis() -> MagicMock:
    store: dict[str, str] = {}

    mock = MagicMock()
    mock.setex.side_effect = lambda key, ttl, val: store.update({key: val})
    mock.get.side_effect = lambda key: store.get(key)
    mock.delete.side_effect = lambda key: store.pop(key, None)
    mock.ttl.return_value = 120
    mock.scan_iter.return_value = []
    return mock


class TestApprovalGate:
    def test_approve_before_timeout(self):
        redis_mock = _mock_redis()
        gate = ApprovalGate(redis_mock, poll_interval=0.01)

        # aprobar inmediatamente en un hilo paralelo
        import threading
        def _approve():
            time.sleep(0.05)
            pending = [k for k in redis_mock.setex.call_args_list]
            # extraer el request_id de la última llamada a setex
            last_call = redis_mock.setex.call_args_list[-1]
            key = last_call[0][0]
            request_id = key.split(":")[-1]
            gate.approve(request_id, decided_by="op_test")

        t = threading.Thread(target=_approve, daemon=True)
        t.start()
        req = gate.request("isolate_host", "10.0.0.5", timeout=5)
        assert req.status == ApprovalStatus.APPROVED
        t.join(timeout=2)

    def test_deny_raises_approval_denied(self):
        redis_mock = _mock_redis()
        gate = ApprovalGate(redis_mock, poll_interval=0.01)

        import threading
        def _deny():
            time.sleep(0.05)
            last_call = redis_mock.setex.call_args_list[-1]
            key = last_call[0][0]
            request_id = key.split(":")[-1]
            gate.deny(request_id, decided_by="op_test")

        t = threading.Thread(target=_deny, daemon=True)
        t.start()
        with pytest.raises(ApprovalDenied):
            gate.request("isolate_host", "10.0.0.5", timeout=5)
        t.join(timeout=2)

    def test_timeout_raises_approval_denied(self):
        redis_mock = _mock_redis()
        # simular TTL expirado devolviendo None
        redis_mock.get.return_value = None
        gate = ApprovalGate(redis_mock, poll_interval=0.01)
        with pytest.raises(ApprovalDenied):
            gate.request("block_ip", "192.168.1.1", timeout=1)

    def test_approve_returns_false_if_not_found(self):
        redis_mock = _mock_redis()
        gate = ApprovalGate(redis_mock)
        assert gate.approve("nonexistent-id") is False

    def test_deny_returns_false_if_not_found(self):
        redis_mock = _mock_redis()
        gate = ApprovalGate(redis_mock)
        assert gate.deny("nonexistent-id") is False

    def test_approval_request_serialization(self):
        req = ApprovalRequest(
            request_id="r1",
            action="isolate",
            target="10.0.0.1",
            risk_level="high",
            operator_id="op_1",
            created_at="2026-07-13T00:00:00Z",
            timeout_secs=600,
        )
        d = req.to_dict()
        req2 = ApprovalRequest.from_dict(d)
        assert req2.request_id == req.request_id
        assert req2.status == ApprovalStatus.PENDING

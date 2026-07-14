"""Tests unitarios para Muralla (Playbook Guard determinista)."""

import hashlib
import json

import pytest

from pantheon.muralla.allowlist import PlaybookAllowlist, PlaybookMeta
from pantheon.muralla.validator import (
    BlockIpParams,
    IsolateHostParams,
    MurallaDecision,
    MurallaGuard,
    SimScope,
    ValidationResult,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

_SCOPE_DATA = {
    "allowed_networks": ["192.168.100.0/24", "10.0.100.0/24"],
    "excluded_ips": ["192.168.100.1"],
    "allowed_port_ranges": [{"from": 1, "to": 1024}],
    "max_isolation_duration_secs": 3600,
    "allowed_playbook_actions": ["isolate_host", "block_ip"],
}

_VALID_HASH = "a" * 64

_PLAYBOOKS = [
    PlaybookMeta(
        id="pb-test-isolate",
        name="Test Isolate",
        action="isolate_host",
        parameters_schema={},
        emergency=False,
        requires_approval=True,
        hash_sha256=_VALID_HASH,
    ),
    PlaybookMeta(
        id="pb-test-block",
        name="Test Block IP",
        action="block_ip",
        parameters_schema={},
        emergency=False,
        requires_approval=True,
        hash_sha256="b" * 64,
    ),
]


def _make_guard() -> MurallaGuard:
    allowlist = PlaybookAllowlist(_PLAYBOOKS)
    scope = SimScope(_SCOPE_DATA)
    return MurallaGuard(allowlist, scope)


# ── SimScope ──────────────────────────────────────────────────────────────────

class TestSimScope:
    def _scope(self) -> SimScope:
        return SimScope(_SCOPE_DATA)

    def test_ip_in_network_is_in_scope(self):
        assert self._scope().is_ip_in_scope("192.168.100.50") is True

    def test_excluded_ip_is_out_of_scope(self):
        assert self._scope().is_ip_in_scope("192.168.100.1") is False

    def test_ip_outside_network_is_out_of_scope(self):
        assert self._scope().is_ip_in_scope("172.16.0.1") is False

    def test_invalid_ip_returns_false(self):
        assert self._scope().is_ip_in_scope("not.an.ip") is False

    def test_allowed_action(self):
        assert self._scope().is_action_allowed("isolate_host") is True
        assert self._scope().is_action_allowed("delete_everything") is False

    def test_port_in_range_allowed(self):
        assert self._scope().is_port_allowed(443) is True
        assert self._scope().is_port_allowed(8080) is False


# ── PlaybookAllowlist ─────────────────────────────────────────────────────────

class TestPlaybookAllowlist:
    def test_lookup_by_hash_found(self):
        al = PlaybookAllowlist(_PLAYBOOKS)
        meta = al.lookup_by_hash(_VALID_HASH)
        assert meta is not None
        assert meta.id == "pb-test-isolate"

    def test_lookup_by_hash_not_found(self):
        al = PlaybookAllowlist(_PLAYBOOKS)
        assert al.lookup_by_hash("0" * 64) is None

    def test_lookup_by_id(self):
        al = PlaybookAllowlist(_PLAYBOOKS)
        assert al.lookup_by_id("pb-test-block") is not None

    def test_compute_hash_deterministic(self):
        pb = {"id": "test", "action": "isolate_host"}
        h1 = PlaybookAllowlist.compute_hash(pb)
        h2 = PlaybookAllowlist.compute_hash(pb)
        assert h1 == h2

    def test_compute_hash_canonical(self):
        pb1 = {"b": 2, "a": 1}
        pb2 = {"a": 1, "b": 2}
        assert PlaybookAllowlist.compute_hash(pb1) == PlaybookAllowlist.compute_hash(pb2)

    def test_registered_hashes_set(self):
        al = PlaybookAllowlist(_PLAYBOOKS)
        assert _VALID_HASH in al.registered_hashes


# ── MurallaGuard ─────────────────────────────────────────────────────────────

class TestMurallaGuard:
    def test_valid_playbook_allowed(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "192.168.100.50", "duration_secs": 300},
        )
        assert decision.result == ValidationResult.ALLOWED

    def test_unknown_hash_rejected(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash="0" * 64,
            parameters={"target_ip": "192.168.100.50", "duration_secs": 300},
        )
        assert decision.result == ValidationResult.REJECTED
        assert "allowlist" in decision.reason.lower() or "no registrado" in decision.reason.lower()

    def test_invalid_ip_parameter_rejected(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "not.valid.ip", "duration_secs": 300},
        )
        assert decision.result == ValidationResult.REJECTED

    def test_duration_out_of_range_rejected(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "192.168.100.50", "duration_secs": 50},
        )
        assert decision.result == ValidationResult.REJECTED

    def test_excluded_ip_rejected_by_scope(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "192.168.100.1", "duration_secs": 300},
        )
        assert decision.result == ValidationResult.REJECTED
        assert "scope" in decision.reason.lower() or "excluida" in decision.reason.lower()

    def test_ip_outside_network_rejected(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "8.8.8.8", "duration_secs": 300},
        )
        assert decision.result == ValidationResult.REJECTED

    def test_decision_includes_playbook_meta_on_allow(self):
        guard = _make_guard()
        decision = guard.validate(
            playbook_hash=_VALID_HASH,
            parameters={"target_ip": "10.0.100.50", "duration_secs": 120},
        )
        assert decision.playbook_meta is not None
        assert decision.playbook_meta.id == "pb-test-isolate"


# ── Pydantic param models ─────────────────────────────────────────────────────

class TestParamModels:
    def test_isolate_valid(self):
        p = IsolateHostParams(target_ip="10.0.0.1", duration_secs=300)
        assert p.target_ip == "10.0.0.1"

    def test_isolate_invalid_ip(self):
        with pytest.raises(Exception):
            IsolateHostParams(target_ip="999.999.999.999", duration_secs=300)

    def test_isolate_duration_too_short(self):
        with pytest.raises(Exception):
            IsolateHostParams(target_ip="10.0.0.1", duration_secs=10)

    def test_block_valid(self):
        p = BlockIpParams(target_ip="10.0.0.1", direction="inbound", duration_secs=3600)
        assert p.direction == "inbound"

    def test_block_invalid_direction(self):
        with pytest.raises(Exception):
            BlockIpParams(target_ip="10.0.0.1", direction="sideways", duration_secs=3600)

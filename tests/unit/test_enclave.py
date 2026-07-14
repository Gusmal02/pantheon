"""Tests unitarios para el pre-commit log (enclave) de Pantheon."""

import json
import tempfile
from pathlib import Path

import pytest

from pantheon.audit.enclave import (
    PreCommitLog,
    compute_chain_hash,
    genesis_hash,
    verify_signature,
)


class TestChainHash:
    def test_deterministic(self):
        h1 = compute_chain_hash("action", "ts", "op", "nonce", "prev")
        h2 = compute_chain_hash("action", "ts", "op", "nonce", "prev")
        assert h1 == h2

    def test_different_action_different_hash(self):
        h1 = compute_chain_hash("action1", "ts", "op", "nonce", "prev")
        h2 = compute_chain_hash("action2", "ts", "op", "nonce", "prev")
        assert h1 != h2

    def test_hex_64_chars(self):
        h = compute_chain_hash("a", "b", "c", "d", "e")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_genesis_hash_deterministic(self):
        assert genesis_hash("session-1") == genesis_hash("session-1")

    def test_genesis_hash_different_sessions(self):
        assert genesis_hash("session-1") != genesis_hash("session-2")


class TestPreCommitLog:
    def _log(self, session_id: str = "test-session") -> tuple[PreCommitLog, Path]:
        tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
        path = Path(tmp.name)
        tmp.close()
        path.unlink()
        log = PreCommitLog(session_id=session_id, log_path=path, enclave_key="a" * 64)
        return log, path

    def test_write_creates_file(self):
        log, path = self._log()
        log.write(entry_id="e1", action="test_action", operator_id="op_1")
        assert path.exists()
        path.unlink()

    def test_write_appends_valid_json(self):
        log, path = self._log()
        log.write(entry_id="e1", action="action_a", operator_id="op_1")
        log.write(entry_id="e2", action="action_b", operator_id="op_1")
        lines = [json.loads(l) for l in path.read_text().strip().split("\n")]
        assert len(lines) == 2
        assert lines[0]["action"] == "action_a"
        assert lines[1]["action"] == "action_b"
        path.unlink()

    def test_chain_hash_links(self):
        log, path = self._log()
        e1 = log.write(entry_id="e1", action="first", operator_id="op_1")
        e2 = log.write(entry_id="e2", action="second", operator_id="op_1")
        # el hash de e2 depende del chain_hash de e1
        expected = compute_chain_hash(
            e2.action, e2.timestamp, e2.operator_id, e2.nonce, e1.chain_hash
        )
        assert e2.chain_hash == expected
        path.unlink()

    def test_hmac_signature_valid(self):
        log, path = self._log()
        entry = log.write(entry_id="e1", action="verify_me", operator_id="op_1")
        assert verify_signature(entry, key="a" * 64)
        path.unlink()

    def test_tampered_entry_fails_verification(self):
        log, path = self._log()
        entry = log.write(entry_id="e1", action="legit", operator_id="op_1")
        entry.action = "tampered"
        assert not verify_signature(entry, key="a" * 64)
        path.unlink()

    def test_verify_chain_passes_on_valid_log(self):
        log, path = self._log(session_id="chain-ok")
        for i in range(5):
            log.write(entry_id=f"e{i}", action=f"action_{i}", operator_id="op_1")
        ok, count = log.verify_chain()
        assert ok is True
        assert count == 5
        path.unlink()

    def test_verify_chain_empty_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.log"
            log = PreCommitLog(session_id="empty", log_path=path, enclave_key="a" * 64)
            ok, count = log.verify_chain()
            assert ok is True
            assert count == 0

    def test_recovery_after_restart(self):
        log, path = self._log(session_id="restart-test")
        e1 = log.write(entry_id="e1", action="before_restart", operator_id="op_1")

        log2 = PreCommitLog(session_id="restart-test", log_path=path, enclave_key="a" * 64)
        e2 = log2.write(entry_id="e2", action="after_restart", operator_id="op_1")

        expected = compute_chain_hash(
            e2.action, e2.timestamp, e2.operator_id, e2.nonce, e1.chain_hash
        )
        assert e2.chain_hash == expected
        path.unlink()

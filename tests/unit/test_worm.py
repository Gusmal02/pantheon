"""Tests unitarios para el módulo WORM."""

import pytest

from pantheon.audit.worm import WORMError, WORMReceipt, replicate_to_worm


class TestWorm:
    def test_skipped_when_disabled(self):
        receipt = replicate_to_worm(
            entry_id="e1",
            session_id="sess-1",
            chain_hash="abc",
            payload={"event": "test"},
            enabled=False,
        )
        assert receipt.skipped is True
        assert receipt.confirmed is False

    def test_skipped_receipt_has_object_key(self):
        receipt = replicate_to_worm(
            entry_id="entry-42",
            session_id="sess-1",
            chain_hash="abc",
            payload={},
            enabled=False,
        )
        assert "entry-42" in receipt.object_key
        assert "sess-1" in receipt.object_key

    def test_worm_error_on_unreachable(self):
        with pytest.raises(WORMError):
            replicate_to_worm(
                entry_id="e1",
                session_id="sess-1",
                chain_hash="abc",
                payload={},
                endpoint="http://localhost:19999/nonexistent",
                enabled=True,
                timeout=1,
            )

    def test_receipt_is_dataclass(self):
        receipt = replicate_to_worm(
            entry_id="e1",
            session_id="sess-1",
            chain_hash="abc",
            payload={},
            enabled=False,
        )
        assert hasattr(receipt, "object_key")
        assert hasattr(receipt, "etag")
        assert hasattr(receipt, "confirmed")
        assert hasattr(receipt, "timestamp")

"""Tests unitarios para Event Bus y Kill Switch (sin Redis real)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from pantheon.core.event_bus import (
    CHANNEL_KILL,
    STREAM_DECISIONS,
    STREAM_EVENTS,
    KillSwitch,
    publish_decision,
    publish_event,
)


class TestEventBusConstants:
    def test_stream_names_prefixed_with_pantheon(self):
        assert STREAM_EVENTS.startswith("pantheon:")
        assert STREAM_DECISIONS.startswith("pantheon:")
        assert CHANNEL_KILL.startswith("pantheon:")

    def test_kill_channel_different_from_ares(self):
        # garantiza que el kill switch de Pantheon no interfiere con Ares
        assert "ares" not in CHANNEL_KILL


class TestPublishEvent:
    def test_publish_event_calls_xadd(self):
        mock_client = MagicMock()
        mock_client.xadd.return_value = "1-0"
        event = {"source_ip": "10.0.0.1", "anomaly_score": 0.9}
        msg_id = publish_event(event, mock_client)
        mock_client.xadd.assert_called_once()
        call_args = mock_client.xadd.call_args
        assert STREAM_EVENTS in call_args[0]
        assert msg_id == "1-0"

    def test_publish_decision_calls_xadd(self):
        mock_client = MagicMock()
        mock_client.xadd.return_value = "2-0"
        decision = {"hypothesis": "lateral movement via SSH"}
        msg_id = publish_decision(decision, mock_client)
        mock_client.xadd.assert_called_once()
        assert msg_id == "2-0"

    def test_event_payload_serialized_as_json(self):
        mock_client = MagicMock()
        event = {"key": "value", "nested": {"a": 1}}
        publish_event(event, mock_client)
        call_args = mock_client.xadd.call_args
        payload_str = call_args[0][1]["payload"]
        assert json.loads(payload_str) == event


class TestKillSwitch:
    def test_trigger_publishes_to_channel(self):
        mock_client = MagicMock()
        mock_client.publish.return_value = 3
        result = KillSwitch.trigger(mock_client, reason="test")
        mock_client.publish.assert_called_once_with(CHANNEL_KILL, "test")
        assert result == 3

    def test_callback_called_on_message(self):
        mock_client = MagicMock()
        mock_client.pubsub.return_value = MagicMock()
        called = []
        ks = KillSwitch(mock_client, abort_callback=lambda: called.append(True))
        ks._handle({"type": "message", "data": "abort"})
        assert called == [True]

    def test_non_message_type_ignored(self):
        mock_client = MagicMock()
        called = []
        ks = KillSwitch(mock_client, abort_callback=lambda: called.append(True))
        ks._handle({"type": "subscribe", "data": 1})
        assert called == []

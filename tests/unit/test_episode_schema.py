"""Tests unitarios para el esquema de episodio de Ornith."""

import uuid
from datetime import datetime, timezone

import pytest

from pantheon.ornith.episode_schema import Episode, TTPTag


class TestEpisodeSchema:
    def _minimal(self) -> dict:
        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc),
            "anomaly_signature": "SSH brute-force desde 10.0.0.5",
            "hypothesis": "Movimiento lateral vía SSH tras comprometer credenciales",
        }

    def test_minimal_episode_valid(self):
        ep = Episode(**self._minimal())
        assert ep.hypothesis != ""
        assert ep.ttp_tags == []
        assert ep.iocs_extraidos == []
        assert ep.playbook_applied is None

    def test_ttp_tags_enum_values(self):
        data = self._minimal()
        data["ttp_tags"] = [TTPTag.LATERAL_MOVEMENT, TTPTag.EXECUTION]
        ep = Episode(**data)
        assert TTPTag.LATERAL_MOVEMENT.value in ep.ttp_tags

    def test_invalid_field_raises(self):
        data = self._minimal()
        data.pop("hypothesis")
        with pytest.raises(Exception):
            Episode(**data)

    def test_model_dump_serializable(self):
        ep = Episode(**self._minimal())
        dumped = ep.model_dump(mode="json")
        assert isinstance(dumped["timestamp"], str)
        assert isinstance(dumped["ttp_tags"], list)

    def test_campaign_id_optional(self):
        ep = Episode(**self._minimal())
        assert ep.campaign_id is None

    def test_iocs_list_populated(self):
        data = self._minimal()
        data["iocs_extraidos"] = ["192.168.1.1", "CVE-2021-44228"]
        ep = Episode(**data)
        assert "192.168.1.1" in ep.iocs_extraidos

    def test_analyst_feedback_optional(self):
        ep = Episode(**self._minimal())
        assert ep.analyst_feedback is None

    def test_evidence_retrieved_default_empty(self):
        ep = Episode(**self._minimal())
        assert ep.evidence_retrieved == []

    # ── Nuevos campos de sesión (campaign granularity) ────────────────────────

    def test_source_ip_optional_defaults_none(self):
        ep = Episode(**self._minimal())
        assert ep.source_ip is None

    def test_source_ip_stored(self):
        data = self._minimal()
        data["source_ip"] = "10.10.10.88"
        ep = Episode(**data)
        assert ep.source_ip == "10.10.10.88"

    def test_window_start_end_optional(self):
        ep = Episode(**self._minimal())
        assert ep.window_start is None
        assert ep.window_end is None

    def test_window_duration_with_both_set(self):
        from datetime import timezone, timedelta
        data = self._minimal()
        t0 = datetime.now(timezone.utc)
        data["window_start"] = t0
        data["window_end"] = t0 + timedelta(seconds=120)
        ep = Episode(**data)
        assert ep.window_duration_seconds == pytest.approx(120.0)

    def test_window_duration_none_when_fields_missing(self):
        ep = Episode(**self._minimal())
        assert ep.window_duration_seconds is None

    def test_technique_sequence_defaults_empty(self):
        ep = Episode(**self._minimal())
        assert ep.technique_sequence == []

    def test_technique_sequence_stored_in_order(self):
        data = self._minimal()
        data["technique_sequence"] = ["T1046", "T1021", "T1135", "T1083"]
        ep = Episode(**data)
        assert ep.technique_sequence == ["T1046", "T1021", "T1135", "T1083"]

    def test_full_campaign_episode_serializable(self):
        from datetime import timezone, timedelta
        t0 = datetime.now(timezone.utc)
        data = self._minimal()
        data.update({
            "source_ip": "203.0.113.5",
            "window_start": t0,
            "window_end": t0 + timedelta(minutes=3),
            "technique_sequence": ["T1046", "T1021", "T1003"],
            "campaign_id": "ares-run-001",
            "ttp_tags": [TTPTag.LATERAL_MOVEMENT, TTPTag.RECONNAISSANCE],
        })
        ep = Episode(**data)
        dumped = ep.model_dump(mode="json")
        assert dumped["source_ip"] == "203.0.113.5"
        assert dumped["campaign_id"] == "ares-run-001"
        assert dumped["technique_sequence"] == ["T1046", "T1021", "T1003"]
        assert isinstance(dumped["window_start"], str)

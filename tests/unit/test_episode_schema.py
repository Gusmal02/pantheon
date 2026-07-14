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

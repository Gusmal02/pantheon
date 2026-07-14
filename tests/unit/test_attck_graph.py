"""Tests unitarios para el grafo ATT&CK."""

import json
import pytest

from pantheon.attck_graph.graph import ATTCKGraph


class TestATTCKGraph:
    def _graph(self) -> ATTCKGraph:
        return ATTCKGraph()

    def test_has_nodes(self):
        g = self._graph()
        assert len(g.technique_ids) > 0

    def test_has_edges(self):
        g = self._graph()
        assert g.edge_count > 0

    def test_successors_of_known_technique(self):
        g = self._graph()
        successors = g.get_related_techniques("T1190", direction="successors")
        assert len(successors) > 0
        # T1190 → T1059 y T1078 según el grafo por defecto
        assert "T1059" in successors or "T1078" in successors

    def test_predecessors_of_known_technique(self):
        g = self._graph()
        preds = g.get_related_techniques("T1059", direction="predecessors")
        assert len(preds) > 0

    def test_unknown_technique_returns_empty(self):
        g = self._graph()
        assert g.get_related_techniques("T9999") == []

    def test_expand_hypothesis_excludes_observed(self):
        g = self._graph()
        observed = ["T1190", "T1059"]
        candidates = g.expand_hypothesis(observed, max_candidates=5)
        for tech in candidates:
            assert tech not in observed

    def test_expand_hypothesis_returns_list(self):
        g = self._graph()
        result = g.expand_hypothesis(["T1190"])
        assert isinstance(result, list)

    def test_get_tactic_known(self):
        g = self._graph()
        assert g.get_tactic("T1190") == "initial-access"
        assert g.get_tactic("T1059") == "execution"

    def test_get_tactic_unknown(self):
        g = self._graph()
        assert g.get_tactic("T9999") == "unknown"

    def test_depth_2_returns_more_than_depth_1(self):
        g = self._graph()
        depth1 = g.get_related_techniques("T1190", depth=1)
        depth2 = g.get_related_techniques("T1190", depth=2)
        assert len(depth2) >= len(depth1)

    def test_from_json(self, tmp_path):
        data = {
            "relations": [["T1001", "T1002"], ["T1002", "T1003"]],
            "tactic_map": {"T1001": "tactic-a", "T1002": "tactic-b"},
        }
        path = tmp_path / "attck.json"
        path.write_text(json.dumps(data))
        g = ATTCKGraph.from_json(path)
        assert "T1002" in g.get_related_techniques("T1001")

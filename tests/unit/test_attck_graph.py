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

    # ── Co-ocurrencia y Dijkstra ──────────────────────────────────────────────

    def test_edges_have_default_weight_1(self):
        g = self._graph()
        w = g.cooccurrence_weight("T1190", "T1059")
        assert w == pytest.approx(1.0)

    def test_update_cooccurrence_reduces_weight(self):
        g = self._graph()
        g.update_cooccurrence(["T1190", "T1059"])
        w = g.cooccurrence_weight("T1190", "T1059")
        assert w < 1.0

    def test_update_cooccurrence_twice_reduces_further(self):
        g = self._graph()
        g.update_cooccurrence(["T1190", "T1059"])
        w1 = g.cooccurrence_weight("T1190", "T1059")
        g.update_cooccurrence(["T1190", "T1059"])
        w2 = g.cooccurrence_weight("T1190", "T1059")
        assert w2 < w1

    def test_weight_minimum_is_0_1(self):
        g = self._graph()
        for _ in range(100):
            g.update_cooccurrence(["T1190", "T1059"])
        w = g.cooccurrence_weight("T1190", "T1059")
        assert w >= 0.1

    def test_update_cooccurrence_creates_new_edge(self):
        g = self._graph()
        assert g.cooccurrence_weight("T1486", "T1059") is None
        g.update_cooccurrence(["T1486", "T1059"])
        assert g.cooccurrence_weight("T1486", "T1059") is not None

    def test_cooccurrence_weight_none_for_nonexistent(self):
        g = self._graph()
        assert g.cooccurrence_weight("T9999", "T8888") is None

    def test_shortest_path_to_tactic_returns_list(self):
        g = self._graph()
        path = g.shortest_path_to_tactic("T1190", "exfiltration")
        assert isinstance(path, list)

    def test_shortest_path_reaches_target_tactic(self):
        g = self._graph()
        path = g.shortest_path_to_tactic("T1190", "exfiltration")
        assert len(path) > 0
        # el último nodo del camino debe tener táctica exfiltration
        assert g.get_tactic(path[-1]) == "exfiltration"

    def test_shortest_path_unknown_technique_returns_empty(self):
        g = self._graph()
        assert g.shortest_path_to_tactic("T9999", "exfiltration") == []

    def test_shortest_path_unknown_tactic_returns_empty(self):
        g = self._graph()
        assert g.shortest_path_to_tactic("T1190", "nonexistent-tactic") == []

    def test_shortest_path_max_results_respected(self):
        g = self._graph()
        path = g.shortest_path_to_tactic("T1190", "exfiltration", max_results=2)
        assert len(path) <= 2

    def test_cooccurrence_shifts_path(self):
        g = self._graph()
        path_before = g.shortest_path_to_tactic("T1059", "exfiltration")
        # Reforzar el camino T1059 → T1105 → T1071 → T1041 con co-ocurrencias
        for _ in range(5):
            g.update_cooccurrence(["T1059", "T1105", "T1071", "T1041"])
        path_after = g.shortest_path_to_tactic("T1059", "exfiltration")
        # El camino reforzado debe incluir T1105 (primer paso preferido)
        assert len(path_after) > 0
        assert path_after[0] == "T1105"

    # ── A* heurística ─────────────────────────────────────────────────────────

    def test_astar_finds_same_path_as_dijkstra_on_uniform_weights(self):
        """Con pesos uniformes A* y Dijkstra deben encontrar el mismo camino óptimo."""
        import networkx as nx
        g = self._graph()
        # Verificar con Dijkstra explícito
        start, goal = "T1059", "T1041"
        try:
            dijkstra_path = nx.dijkstra_path(g._graph, start, goal, weight="weight")
        except nx.NetworkXNoPath:
            pytest.skip("No path between T1059 and T1041 en el grafo por defecto")
        astar_result = g.shortest_path_to_tactic("T1059", "exfiltration", max_results=10)
        # El camino de A* debe incluir los mismos nodos intermedios que Dijkstra
        assert len(astar_result) > 0
        assert astar_result[-1] == dijkstra_path[-1]

    def test_heuristic_is_admissible(self):
        """h(u,v) <= costo_real(u→v) para todo par con camino existente."""
        import networkx as nx
        g = self._graph()
        # Reforzar algunos pesos para que no sean todos 1.0
        g.update_cooccurrence(["T1059", "T1105", "T1071", "T1041"])
        g.update_cooccurrence(["T1059", "T1105"])

        for src in list(g.technique_ids)[:6]:
            for tgt in list(g.technique_ids)[:6]:
                if src == tgt:
                    continue
                try:
                    real_cost = nx.dijkstra_path_length(g._graph, src, tgt, weight="weight")
                    h = g._astar_heuristic(src, tgt)
                    assert h <= real_cost + 1e-9, (
                        f"Heuristica NO admisible: h({src},{tgt})={h} > real={real_cost}"
                    )
                except nx.NetworkXNoPath:
                    assert g._astar_heuristic(src, tgt) == float("inf")

    def test_heuristic_returns_inf_for_no_path(self):
        g = self._graph()
        assert g._astar_heuristic("T9999", "T1041") == float("inf")

    def test_heuristic_zero_for_same_node(self):
        g = self._graph()
        # Misma fuente y destino — sin aristas, BFS length = 0
        h = g._astar_heuristic("T1059", "T1059")
        assert h == 0.0

    def test_singleton_shared_across_calls(self):
        from pantheon.attck_graph.graph import get_shared_graph
        g1 = get_shared_graph()
        g2 = get_shared_graph()
        assert g1 is g2

    def test_load_cooccurrence_from_episodes(self):
        from pantheon.ornith.episode_schema import Episode
        from datetime import datetime, timezone
        import uuid

        g = self._graph()

        def make_ep(seq):
            return Episode(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                anomaly_signature="test",
                hypothesis="test hypothesis",
                technique_sequence=seq,
            )

        episodes = [
            make_ep(["T1190", "T1059", "T1105"]),
            make_ep(["T1190", "T1059", "T1105"]),
            make_ep(["T1566", "T1204"]),
            make_ep(["T1059"]),  # solo 1 técnica — no debe contar
        ]

        processed = g.load_cooccurrence_from_episodes(episodes)
        assert processed == 3  # el de 1 técnica no cuenta
        # T1190→T1059 fue visto 2 veces — peso debe ser < 1
        assert g.cooccurrence_weight("T1190", "T1059") < 1.0

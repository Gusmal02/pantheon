"""
Grafo ATT&CK con NetworkX para expansión de hipótesis en Hermes.

Construye un grafo dirigido donde:
  - Nodos = tácticas y técnicas MITRE ATT&CK
  - Aristas = relaciones de secuencia típica de campaña (A → B significa
    que B suele seguir a A en ataques reales)

El grafo se carga desde datos STIX (scripts/fetch_attack_stix.py) o
desde un JSON simplificado en data/attck_graph.json.

Uso principal:
  graph.get_related_techniques("T1190") → ["T1059", "T1078", ...]
  graph.expand_hypothesis(["T1190", "T1059"]) → técnicas vecinas probables
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import networkx as nx

# ── Singleton compartido entre pipeline, Ornith y Hermes ─────────────────────
_shared: "ATTCKGraph | None" = None


def get_shared_graph() -> "ATTCKGraph":
    """Devuelve la instancia singleton de ATTCKGraph.

    Garantiza que pipeline.py, ornith/client.py y hermes/nodes.py
    operan sobre el mismo grafo: los pesos actualizados por Ornith
    son inmediatamente visibles para A* en Hermes.
    """
    global _shared
    if _shared is None:
        _shared = ATTCKGraph()
    return _shared


_DEFAULT_RELATIONS = [
    ("T1595", "T1190"),   # Recon → Exploit Public-Facing App
    ("T1190", "T1059"),   # Exploit → Command & Scripting
    ("T1190", "T1078"),   # Exploit → Valid Accounts
    ("T1078", "T1021"),   # Valid Accounts → Remote Services
    ("T1021", "T1003"),   # Remote Services → Credential Dumping
    ("T1003", "T1078"),   # Cred Dump → Valid Accounts (lateral)
    ("T1059", "T1105"),   # Scripting → Ingress Tool Transfer
    ("T1105", "T1071"),   # Tool Transfer → C2 App Layer
    ("T1071", "T1041"),   # C2 → Exfiltration over C2
    ("T1486", "T1490"),   # Ransomware → Inhibit Recovery
    ("T1566", "T1204"),   # Phishing → User Execution
    ("T1204", "T1059"),   # User Execution → Scripting
    ("T1059", "T1547"),   # Scripting → Boot Autostart
]

_TACTIC_MAP: dict[str, str] = {
    "T1595": "reconnaissance",
    "T1190": "initial-access",
    "T1566": "initial-access",
    "T1078": "persistence",
    "T1547": "persistence",
    "T1059": "execution",
    "T1204": "execution",
    "T1003": "credential-access",
    "T1021": "lateral-movement",
    "T1105": "command-and-control",
    "T1071": "command-and-control",
    "T1041": "exfiltration",
    "T1486": "impact",
    "T1490": "impact",
}


class ATTCKGraph:
    """
    Grafo de técnicas ATT&CK para expansión de hipótesis.

    Args:
        relations — lista de (source_technique_id, target_technique_id)
        tactic_map — dict {technique_id: tactic_name}

    Pesos de aristas:
        Todas las aristas inician con weight=1.0 (uniform).
        update_cooccurrence() reduce el peso de pares que co-ocurren en episodios
        reales: weight = 1 / count. Menor peso = camino más probable para Dijkstra.
    """

    def __init__(
        self,
        relations: list[tuple[str, str]] = _DEFAULT_RELATIONS,
        tactic_map: dict[str, str] = _TACTIC_MAP,
    ) -> None:
        self._graph = nx.DiGraph()
        self._tactic_map = dict(tactic_map)
        self._cooccurrence: dict[tuple[str, str], int] = {}
        for src, tgt in relations:
            self._graph.add_edge(src, tgt, weight=1.0)
        # añadir tácticas como atributo de nodo
        for node in self._graph.nodes:
            self._graph.nodes[node]["tactic"] = self._tactic_map.get(node, "unknown")

    @classmethod
    def from_json(cls, path: Path | str) -> "ATTCKGraph":
        """Carga el grafo desde un JSON con formato {relations: [[src, tgt], ...]}."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        relations = [tuple(r) for r in data.get("relations", [])]
        tactic_map = data.get("tactic_map", _TACTIC_MAP)
        return cls(relations=relations, tactic_map=tactic_map)

    def get_related_techniques(
        self,
        technique_id: str,
        direction: str = "successors",
        depth: int = 1,
    ) -> list[str]:
        """
        Devuelve técnicas relacionadas con la indicada.

        Args:
            technique_id — ID de técnica ATT&CK (ej. "T1190")
            direction    — "successors" (qué puede venir después) o
                           "predecessors" (qué suele preceder)
            depth        — profundidad de búsqueda en el grafo
        """
        if technique_id not in self._graph:
            return []

        if direction == "successors":
            neighbor_fn = self._graph.successors
        else:
            neighbor_fn = self._graph.predecessors

        if depth == 1:
            return list(neighbor_fn(technique_id))

        visited = set()
        frontier = {technique_id}
        for _ in range(depth):
            next_frontier = set()
            for node in frontier:
                for neighbor in neighbor_fn(node):
                    if neighbor not in visited and neighbor != technique_id:
                        next_frontier.add(neighbor)
            visited.update(frontier)
            frontier = next_frontier
        return list(visited - {technique_id})

    def expand_hypothesis(
        self,
        observed_techniques: list[str],
        max_candidates: int = 10,
    ) -> list[str]:
        """
        Dado un conjunto de técnicas observadas, sugiere cuáles podrían
        aparecer a continuación en la campaña.
        """
        candidates: dict[str, int] = {}
        for tech in observed_techniques:
            for successor in self.get_related_techniques(tech, direction="successors", depth=2):
                if successor not in observed_techniques:
                    candidates[successor] = candidates.get(successor, 0) + 1

        sorted_candidates = sorted(candidates.items(), key=lambda x: x[1], reverse=True)
        return [tid for tid, _ in sorted_candidates[:max_candidates]]

    def get_tactic(self, technique_id: str) -> str:
        """Devuelve la táctica MITRE de una técnica."""
        return self._tactic_map.get(technique_id, "unknown")

    # ── Co-ocurrencia y Dijkstra (base para A*) ───────────────────────────────

    def update_cooccurrence(self, technique_sequence: list[str]) -> None:
        """Actualiza pesos de aristas a partir de una secuencia de técnicas observadas.

        Por cada par consecutivo (src, tgt) en la secuencia:
          - Incrementa el contador de co-ocurrencia.
          - Recalcula weight = 1 / count (menor = más probable para Dijkstra).
          - Si la arista no existe en el grafo base, la crea (nueva evidencia empírica).

        El mínimo weight posible es 0.1 para evitar colapso numérico.
        """
        for i in range(len(technique_sequence) - 1):
            src, tgt = technique_sequence[i], technique_sequence[i + 1]
            key = (src, tgt)
            self._cooccurrence[key] = self._cooccurrence.get(key, 0) + 1
            weight = max(0.1, 1.0 / (1 + self._cooccurrence[key]))
            if self._graph.has_edge(src, tgt):
                self._graph[src][tgt]["weight"] = weight
            else:
                self._graph.add_edge(src, tgt, weight=weight)
                # propagar tactic_map a nodos nuevos que lleguen por evidencia empírica
                for node in (src, tgt):
                    if node not in self._graph.nodes or "tactic" not in self._graph.nodes[node]:
                        self._graph.nodes[node]["tactic"] = self._tactic_map.get(node, "unknown")

    def _astar_heuristic(self, u: str, v: str) -> float:
        """h(u, v) admisible para A*: BFS_hops(u→v) × min_peso_saliente(u).

        Admisible porque:
          - BFS_hops es el límite inferior de aristas necesarias (sin pesos)
          - min_peso_saliente(u) es el peso mínimo posible por arista desde u
          - por tanto h(u,v) <= costo_real(u→v) siempre

        Se vuelve más informada conforme Ornith acumula episodios: nodos con
        alta co-ocurrencia tienen min_peso menor → A* los explora antes.
        """
        try:
            hops = nx.shortest_path_length(self._graph, u, v)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return float("inf")
        out_weights = [d.get("weight", 1.0) for _, _, d in self._graph.out_edges(u, data=True)]
        min_w = min(out_weights) if out_weights else 0.1
        return hops * min_w

    def shortest_path_to_tactic(
        self,
        start_technique: str,
        target_tactic: str,
        max_results: int = 5,
    ) -> list[str]:
        """A* desde start_technique hacia el nodo con target_tactic de menor costo.

        Devuelve la secuencia de técnicas intermedias (excluye start_technique).
        Retorna lista vacía si no hay camino o la técnica inicial no existe.

        La heurística _astar_heuristic es admisible: garantiza optimalidad.
        Conforme Ornith indexa episodios reales, los pesos bajan y A* guía
        la búsqueda hacia los caminos más frecuentes en campañas reales.
        """
        if start_technique not in self._graph:
            return []

        goal_nodes = [
            n for n in self._graph.nodes
            if self._graph.nodes[n].get("tactic") == target_tactic
            and n != start_technique
        ]
        if not goal_nodes:
            return []

        best_path: list[str] = []
        best_cost = float("inf")
        for goal in goal_nodes:
            try:
                path = nx.astar_path(
                    self._graph,
                    start_technique,
                    goal,
                    heuristic=self._astar_heuristic,
                    weight="weight",
                )
                cost = sum(
                    self._graph[u][v]["weight"] for u, v in zip(path, path[1:])
                )
                if cost < best_cost:
                    best_cost = cost
                    best_path = path
            except nx.NetworkXNoPath:
                continue

        return best_path[1 : max_results + 1]  # excluir nodo inicial

    def load_cooccurrence_from_episodes(self, episodes: list) -> int:
        """Carga pesos de co-ocurrencia desde una lista de episodios de Ornith.

        Cada episodio debe tener un campo technique_sequence: list[str].
        Retorna el número de secuencias procesadas (episodios con >= 2 técnicas).
        """
        processed = 0
        for ep in episodes:
            seq = getattr(ep, "technique_sequence", [])
            if len(seq) >= 2:
                self.update_cooccurrence(seq)
                processed += 1
        return processed

    def cooccurrence_weight(self, src: str, tgt: str) -> float | None:
        """Devuelve el peso actual de la arista (src→tgt), o None si no existe."""
        if self._graph.has_edge(src, tgt):
            return self._graph[src][tgt]["weight"]
        return None

    @property
    def technique_ids(self) -> list[str]:
        return list(self._graph.nodes)

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

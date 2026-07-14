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
    """

    def __init__(
        self,
        relations: list[tuple[str, str]] = _DEFAULT_RELATIONS,
        tactic_map: dict[str, str] = _TACTIC_MAP,
    ) -> None:
        self._graph = nx.DiGraph()
        self._tactic_map = dict(tactic_map)
        for src, tgt in relations:
            self._graph.add_edge(src, tgt)
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

    @property
    def technique_ids(self) -> list[str]:
        return list(self._graph.nodes)

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

"""
Hermes — Agente CRAG (Corrective-RAG) de investigación de amenazas.

Implementado sobre LangGraph. El agente ejecuta un ciclo:
  1. retrieve     → recupera episodios similares desde Ornith
  2. grade_docs   → verifica si los docs son relevantes
  3. rewrite      → reformula la consulta si los docs no son útiles (con budget)
  4. generate     → genera hipótesis con LLM (o fallback determinista)
  5. verify       → comprueba que las hipótesis tengan respaldo en los docs
  6. rank         → pasa candidatos a AcmeRanker para ordenamiento final

Garantías de seguridad:
  - El LLM nunca toma decisiones de autorización — solo genera texto.
  - Si llm=None, el agente usa fallbacks deterministas (modo test/offline).
  - El budget checkpoint evita bucles infinitos.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from langgraph.graph import END, StateGraph

from pantheon.acme.ranker import AcmeRanker
from pantheon.acme.stage1 import HypothesisCandidate
from pantheon.attck_graph.graph import ATTCKGraph
from pantheon.centinela.pipeline import NetworkEvent
from pantheon.hermes.nodes import (
    RetrievalFn,
    budget_checkpoint_node,
    generate_node,
    grade_docs_node,
    retrieve_node,
    rewrite_query_node,
    verify_node,
)
from pantheon.hermes.state import HermesState

import numpy as np


@dataclass
class HermesResult:
    """Resultado completo de una investigación de Hermes."""
    session_id: str
    event: NetworkEvent
    hypotheses: list        # list[RankedHypothesis]
    attck_suggestions: list[str]
    iterations: int
    budget_exhausted: bool
    hypothesis_grounded: bool
    verify_retries: int


def _build_query(event: NetworkEvent) -> str:
    """Construye la consulta inicial a partir del evento de red."""
    return f"anomalous network activity from {event.source_ip} threat hunting"


def _candidates_from_state(
    state: HermesState,
    event: NetworkEvent,
) -> list[HypothesisCandidate]:
    """Construye HypothesisCandidates desde el estado final del grafo."""
    texts = state.get("hypothesis_texts", [])
    attck = state.get("attck_suggestions", [])
    features = np.asarray(event.features, dtype=float)

    candidates = []
    for i, text in enumerate(texts):
        candidates.append(HypothesisCandidate(
            id=f"hyp-{uuid.uuid4().hex[:8]}",
            text=text,
            features=features,
            ttp_tags=attck[:3] if attck else [],
            timestamp_score=1.0,
            playbook_success_rate=0.5,
        ))
    return candidates


class HermesAgent:
    """
    Agente CRAG de investigación de amenazas.

    Args:
        attck_graph     — grafo MITRE ATT&CK para expansión de hipótesis
        ranker          — AcmeRanker para ordenamiento final
        retriever       — función (query, top_k) → list[dict] (Ornith o mock)
        llm             — BaseChatModel o None (modo determinista)
        max_iterations  — máximo de ciclos retrieve-grade-rewrite antes de forzar generate
        max_verify_retries — máximo de reintentos de verificación antes de aceptar
        top_k           — documentos a recuperar por búsqueda
    """

    def __init__(
        self,
        attck_graph: ATTCKGraph,
        ranker: AcmeRanker,
        retriever: RetrievalFn,
        llm: Optional[Any] = None,
        max_iterations: int = 3,
        max_verify_retries: int = 2,
        top_k: int = 5,
    ) -> None:
        self._attck_graph = attck_graph
        self._ranker = ranker
        self._retriever = retriever
        self._llm = llm
        self._max_iterations = max_iterations
        self._max_verify_retries = max_verify_retries
        self._top_k = top_k
        self._compiled = self._build_graph()

    # ── API pública ───────────────────────────────────────────────────────────

    def investigate(self, event: NetworkEvent, operator_id: str = "default") -> HermesResult:
        """
        Investiga un evento de red y devuelve hipótesis rankeadas.

        Args:
            event       — NetworkEvent de Centinela (MODERATE o CRITICAL)
            operator_id — ID del analista para el ranking IPCA

        Returns:
            HermesResult con hipótesis ordenadas y metadatos de la investigación.
        """
        initial_state: HermesState = {
            "query": _build_query(event),
            "source_ip": event.source_ip,
            "event_features": list(event.features),
            "retrieved_docs": [],
            "doc_grades": [],
            "all_docs_relevant": False,
            "hypothesis_texts": [],
            "attck_suggestions": [],
            "hypothesis_grounded": False,
            "iterations": 0,
            "verify_retries": 0,
            "budget_exhausted": False,
        }

        final_state = self._compiled.invoke(initial_state)

        candidates = _candidates_from_state(final_state, event)
        ranked_result = self._ranker.rank(candidates, operator_id) if candidates else None
        hypotheses = ranked_result.ranked if ranked_result else []

        return HermesResult(
            session_id=uuid.uuid4().hex,
            event=event,
            hypotheses=hypotheses,
            attck_suggestions=final_state.get("attck_suggestions", []),
            iterations=final_state.get("iterations", 0),
            budget_exhausted=final_state.get("budget_exhausted", False),
            hypothesis_grounded=final_state.get("hypothesis_grounded", False),
            verify_retries=final_state.get("verify_retries", 0),
        )

    # ── Construcción del grafo ────────────────────────────────────────────────

    def _build_graph(self):
        graph = StateGraph(HermesState)

        # — Nodos —
        graph.add_node("retrieve", self._node_retrieve)
        graph.add_node("grade_docs", self._node_grade_docs)
        graph.add_node("budget_checkpoint", self._node_budget_checkpoint)
        graph.add_node("rewrite_query", self._node_rewrite_query)
        graph.add_node("generate", self._node_generate)
        graph.add_node("verify", self._node_verify)

        # — Flujo principal —
        graph.set_entry_point("retrieve")
        graph.add_edge("retrieve", "grade_docs")

        # grade_docs → budget_checkpoint (siempre)
        graph.add_edge("grade_docs", "budget_checkpoint")

        # budget_checkpoint → generate (si budget agotado o todos docs relevantes)
        #                  → rewrite_query (si quedan iteraciones)
        graph.add_conditional_edges(
            "budget_checkpoint",
            self._route_after_budget,
            {"generate": "generate", "rewrite_query": "rewrite_query"},
        )

        # rewrite → retrieve (ciclo)
        graph.add_edge("rewrite_query", "retrieve")

        # generate → verify
        graph.add_edge("generate", "verify")

        # verify → END o → generate (si aún hay reintentos)
        graph.add_conditional_edges(
            "verify",
            self._route_after_verify,
            {"end": END, "retry": "generate"},
        )

        return graph.compile()

    # ── Wrappers de nodos (cierran sobre self) ────────────────────────────────

    def _node_retrieve(self, state: HermesState) -> dict:
        return retrieve_node(state, self._retriever, self._top_k)

    def _node_grade_docs(self, state: HermesState) -> dict:
        return grade_docs_node(state, self._llm)

    def _node_budget_checkpoint(self, state: HermesState) -> dict:
        return budget_checkpoint_node(state, self._max_iterations)

    def _node_rewrite_query(self, state: HermesState) -> dict:
        return rewrite_query_node(state, self._llm)

    def _node_generate(self, state: HermesState) -> dict:
        return generate_node(state, self._attck_graph, self._llm)

    def _node_verify(self, state: HermesState) -> dict:
        return verify_node(state, self._llm)

    # ── Condiciones de routing ────────────────────────────────────────────────

    def _route_after_budget(self, state: HermesState) -> str:
        """Genera si el budget se agotó o si todos los docs son relevantes."""
        if state.get("budget_exhausted") or state.get("all_docs_relevant"):
            return "generate"
        return "rewrite_query"

    def _route_after_verify(self, state: HermesState) -> str:
        """Reintenta generación si hubo alucinación y queda budget de reintentos."""
        grounded = state.get("hypothesis_grounded", False)
        retries = state.get("verify_retries", 0)
        exhausted = state.get("budget_exhausted", False)

        if grounded or exhausted or retries >= self._max_verify_retries:
            return "end"
        return "retry"

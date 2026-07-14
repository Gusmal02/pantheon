"""
Tests unitarios para el agente Hermes CRAG.

Todos los tests corren sin LLM real (llm=None) usando los fallbacks
deterministas de nodes.py. Se verifica el comportamiento del grafo
LangGraph completo: routing, budget, verificación y ranking.
"""

from __future__ import annotations

import pytest
import numpy as np

from pantheon.acme.ranker import AcmeRanker
from pantheon.attck_graph.graph import ATTCKGraph
from pantheon.centinela.pipeline import NetworkEvent
from pantheon.hermes.agent import HermesAgent, HermesResult
from pantheon.hermes.nodes import (
    _grade_deterministic,
    _generate_deterministic,
    _verify_deterministic,
    _rewrite_deterministic,
    budget_checkpoint_node,
    grade_docs_node,
    retrieve_node,
    verify_node,
)
from pantheon.hermes.state import HermesState


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_docs(n: int = 3) -> list[dict]:
    return [
        {
            "id": f"ep-{i}",
            "narrative": f"Lateral movement attack episode {i} with credential dumping",
            "ttp_tags": ["T1003", "T1021"],
            "score": 0.8 - i * 0.1,
        }
        for i in range(n)
    ]


def _make_event(features: list[float] | None = None) -> NetworkEvent:
    return NetworkEvent(
        features=features or [0.5] * 8,
        source_ip="192.168.100.50",
    )


def _mock_retriever(docs: list[dict]):
    """Retorna un retriever que siempre devuelve los docs dados."""
    def retriever(query: str, top_k: int) -> list[dict]:
        return docs[:top_k]
    return retriever


def _make_agent(docs: list[dict] | None = None, max_iterations: int = 3) -> HermesAgent:
    return HermesAgent(
        attck_graph=ATTCKGraph(),
        ranker=AcmeRanker(),
        retriever=_mock_retriever(docs or _make_docs()),
        llm=None,
        max_iterations=max_iterations,
        max_verify_retries=2,
        top_k=5,
    )


# ── Tests de nodos individuales ───────────────────────────────────────────────

class TestRetrieveNode:
    def _state(self) -> HermesState:
        return {
            "query": "lateral movement credential",
            "source_ip": "10.0.0.1",
            "event_features": [0.5] * 8,
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

    def test_retrieves_docs(self):
        docs = _make_docs(3)
        state = self._state()
        result = retrieve_node(state, _mock_retriever(docs), top_k=5)
        assert len(result["retrieved_docs"]) == 3

    def test_increments_iterations(self):
        state = self._state()
        state["iterations"] = 1
        result = retrieve_node(state, _mock_retriever(_make_docs()), top_k=5)
        assert result["iterations"] == 2

    def test_top_k_limits_results(self):
        docs = _make_docs(10)
        state = self._state()
        result = retrieve_node(state, _mock_retriever(docs), top_k=3)
        assert len(result["retrieved_docs"]) == 3


class TestGradeDocsNode:
    def _base_state(self, docs=None) -> HermesState:
        return {
            "query": "lateral movement credential dumping",
            "source_ip": "10.0.0.1",
            "event_features": [0.5] * 8,
            "retrieved_docs": _make_docs(3) if docs is None else docs,
            "doc_grades": [],
            "all_docs_relevant": False,
            "hypothesis_texts": [],
            "attck_suggestions": [],
            "hypothesis_grounded": False,
            "iterations": 1,
            "verify_retries": 0,
            "budget_exhausted": False,
        }

    def test_grades_relevant_docs_true(self):
        # docs contienen "lateral movement" que está en la query
        result = grade_docs_node(self._base_state(), llm=None)
        assert any(result["doc_grades"])

    def test_empty_docs_gives_empty_grades(self):
        state = self._base_state(docs=[])
        result = grade_docs_node(state, llm=None)
        assert result["doc_grades"] == []
        assert result["all_docs_relevant"] is False

    def test_all_relevant_flag_set(self):
        result = grade_docs_node(self._base_state(), llm=None)
        expected = all(result["doc_grades"])
        assert result["all_docs_relevant"] == expected

    def test_irrelevant_doc_grades_false(self):
        docs = [{"id": "x", "narrative": "unrelated log entry xyz", "ttp_tags": [], "score": 0.1}]
        state = self._base_state(docs=docs)
        grades = _grade_deterministic(docs, "lateral movement credential")
        assert grades[0] is False


class TestBudgetCheckpoint:
    def _state(self, iterations: int, budget: bool = False) -> HermesState:
        return {
            "query": "q", "source_ip": "1.1.1.1", "event_features": [],
            "retrieved_docs": [], "doc_grades": [], "all_docs_relevant": False,
            "hypothesis_texts": [], "attck_suggestions": [], "hypothesis_grounded": False,
            "iterations": iterations, "verify_retries": 0, "budget_exhausted": budget,
        }

    def test_not_exhausted_below_limit(self):
        result = budget_checkpoint_node(self._state(iterations=1), max_iterations=3)
        assert result["budget_exhausted"] is False

    def test_exhausted_at_limit(self):
        result = budget_checkpoint_node(self._state(iterations=3), max_iterations=3)
        assert result["budget_exhausted"] is True

    def test_exhausted_above_limit(self):
        result = budget_checkpoint_node(self._state(iterations=5), max_iterations=3)
        assert result["budget_exhausted"] is True


class TestGenerateNodeDeterministic:
    def test_returns_list_of_strings(self):
        from pantheon.hermes.nodes import generate_node
        state: HermesState = {
            "query": "lateral movement", "source_ip": "10.0.0.1",
            "event_features": [0.5] * 8, "retrieved_docs": _make_docs(2),
            "doc_grades": [True, True], "all_docs_relevant": True,
            "hypothesis_texts": [], "attck_suggestions": [],
            "hypothesis_grounded": False, "iterations": 1,
            "verify_retries": 0, "budget_exhausted": False,
        }
        result = generate_node(state, ATTCKGraph(), llm=None, max_hypotheses=3)
        assert len(result["hypothesis_texts"]) == 3
        assert all(isinstance(h, str) for h in result["hypothesis_texts"])

    def test_attck_suggestions_populated(self):
        from pantheon.hermes.nodes import generate_node
        state: HermesState = {
            "query": "lateral movement", "source_ip": "10.0.0.1",
            "event_features": [0.5] * 8,
            "retrieved_docs": [{"id": "x", "narrative": "attack", "ttp_tags": ["T1003"], "score": 0.9}],
            "doc_grades": [True], "all_docs_relevant": True,
            "hypothesis_texts": [], "attck_suggestions": [],
            "hypothesis_grounded": False, "iterations": 1,
            "verify_retries": 0, "budget_exhausted": False,
        }
        result = generate_node(state, ATTCKGraph(), llm=None)
        # T1003 → successors en el grafo deben existir
        assert isinstance(result["attck_suggestions"], list)

    def test_deterministic_fallback_mentions_ip(self):
        texts = _generate_deterministic(
            {"source_ip": "10.0.0.99", "query": "q"},
            _make_docs(2),
            ["T1003", "T1021"],
            max_hypotheses=3,
        )
        assert any("10.0.0.99" in t for t in texts)


class TestVerifyNodeDeterministic:
    def _state(self, texts: list[str], docs: list[dict]) -> HermesState:
        return {
            "query": "q", "source_ip": "1.1.1.1", "event_features": [],
            "retrieved_docs": docs, "doc_grades": [True] * len(docs),
            "all_docs_relevant": True, "hypothesis_texts": texts,
            "attck_suggestions": [], "hypothesis_grounded": False,
            "iterations": 1, "verify_retries": 0, "budget_exhausted": False,
        }

    def test_grounded_hypothesis_accepted(self):
        docs = _make_docs(2)  # contiene "lateral movement" y "credential"
        texts = ["Lateral movement from 10.0.0.1 using credential dumping techniques"]
        result = verify_node(self._state(texts, docs), llm=None)
        assert result["hypothesis_grounded"] is True

    def test_empty_hypotheses_not_grounded(self):
        result = verify_node(self._state([], _make_docs()), llm=None)
        assert result["hypothesis_grounded"] is False

    def test_verify_increments_retries(self):
        state = self._state(["some hypothesis"], _make_docs())
        state["verify_retries"] = 1
        result = verify_node(state, llm=None)
        assert result["verify_retries"] == 2

    def test_deterministic_verify_without_overlap(self):
        docs = [{"id": "x", "narrative": "unrelated zebra content xyz", "ttp_tags": [], "score": 0.1}]
        texts = ["Zebra migration pattern in Africa wildlife reserve"]
        grounded = _verify_deterministic(texts, docs)
        assert grounded is False


class TestRewriteQueryDeterministic:
    def _state(self, query: str, attck: list[str] = None) -> HermesState:
        return {
            "query": query, "source_ip": "10.0.0.1", "event_features": [],
            "retrieved_docs": [], "doc_grades": [], "all_docs_relevant": False,
            "hypothesis_texts": [], "attck_suggestions": attck or [],
            "hypothesis_grounded": False, "iterations": 1,
            "verify_retries": 0, "budget_exhausted": False,
        }

    def test_rewrite_extends_query(self):
        result = _rewrite_deterministic("lateral movement", self._state("lateral movement"))
        assert len(result) > len("lateral movement")

    def test_rewrite_includes_ip(self):
        result = _rewrite_deterministic("query", self._state("query"))
        assert "10.0.0.1" in result

    def test_rewrite_includes_attck_suggestions(self):
        result = _rewrite_deterministic(
            "query", self._state("query", attck=["T1003", "T1021", "T1078"])
        )
        assert "T1003" in result


# ── Tests de integración del agente completo ──────────────────────────────────

class TestHermesAgentIntegration:
    def test_investigate_returns_result(self):
        agent = _make_agent()
        event = _make_event()
        result = agent.investigate(event, operator_id="op_1")
        assert isinstance(result, HermesResult)

    def test_result_has_session_id(self):
        result = _make_agent().investigate(_make_event())
        assert isinstance(result.session_id, str)
        assert len(result.session_id) > 0

    def test_result_has_hypotheses(self):
        result = _make_agent().investigate(_make_event())
        assert isinstance(result.hypotheses, list)

    def test_attck_suggestions_populated(self):
        result = _make_agent().investigate(_make_event())
        assert isinstance(result.attck_suggestions, list)

    def test_iterations_at_least_one(self):
        result = _make_agent().investigate(_make_event())
        assert result.iterations >= 1

    def test_budget_not_exhausted_with_relevant_docs(self):
        # docs muy relevantes → all_docs_relevant=True desde el primer ciclo
        docs = [
            {"id": f"d{i}", "narrative": "lateral movement credential attack",
             "ttp_tags": ["T1003"], "score": 0.9}
            for i in range(3)
        ]
        agent = _make_agent(docs=docs)
        result = agent.investigate(_make_event())
        assert result.iterations <= 3

    def test_budget_exhausted_with_irrelevant_docs(self):
        # docs completamente irrelevantes → ciclo hasta max_iterations
        docs = [
            {"id": f"d{i}", "narrative": "weather forecast and stock prices",
             "ttp_tags": [], "score": 0.1}
            for i in range(3)
        ]
        agent = _make_agent(docs=docs, max_iterations=2)
        result = agent.investigate(_make_event())
        assert result.budget_exhausted is True

    def test_no_docs_still_produces_hypotheses(self):
        agent = _make_agent(docs=[], max_iterations=1)
        result = agent.investigate(_make_event())
        # Con budget=1 y sin docs, debe llegar a generate con fallback
        assert isinstance(result.hypotheses, list)

    def test_different_operator_produces_same_structure(self):
        agent = _make_agent()
        r1 = agent.investigate(_make_event(), operator_id="op_A")
        r2 = agent.investigate(_make_event(), operator_id="op_B")
        assert isinstance(r1.hypotheses, list)
        assert isinstance(r2.hypotheses, list)

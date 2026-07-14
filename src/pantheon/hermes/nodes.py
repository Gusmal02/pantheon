"""
Nodos del grafo LangGraph de Hermes.

Cada nodo recibe el estado completo y devuelve un dict parcial con
las claves a actualizar. Los nodos son funciones puras: sin efectos
secundarios globales, fácilmente testeables en aislamiento.

El parámetro `llm` es opcional (BaseChatModel). Si es None, los nodos
de generación y verificación usan un fallback determinista — útil para
tests y entornos sin API key configurada.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from pantheon.attck_graph.graph import ATTCKGraph
from pantheon.hermes.state import HermesState

# Tipo del retriever: función que acepta (query, top_k) y devuelve lista de docs
RetrievalFn = Callable[[str, int], list[dict]]

_RELEVANCE_KEYWORDS = [
    "lateral movement", "credential", "exploit", "command", "control",
    "exfil", "ransomware", "phishing", "anomaly", "suspicious", "attack",
    "ioc", "malware", "privilege", "escalation", "persistence",
]


# ── Nodo 1: Recuperación ──────────────────────────────────────────────────────

def retrieve_node(
    state: HermesState,
    retriever: RetrievalFn,
    top_k: int = 5,
) -> dict:
    """Recupera episodios relevantes desde Ornith."""
    docs = retriever(state["query"], top_k)
    return {
        "retrieved_docs": docs,
        "iterations": state.get("iterations", 0) + 1,
    }


# ── Nodo 2: Clasificación de documentos ──────────────────────────────────────

def grade_docs_node(
    state: HermesState,
    llm: Optional[Any] = None,
) -> dict:
    """
    Evalúa si los documentos recuperados son relevantes para la consulta.

    Con LLM: usa un prompt de relevancia binario (yes/no).
    Sin LLM: comprueba solapamiento de palabras clave con la consulta.
    """
    docs = state.get("retrieved_docs", [])
    query_lower = state["query"].lower()

    if not docs:
        return {"doc_grades": [], "all_docs_relevant": False}

    if llm is not None:
        grades = _grade_with_llm(docs, query_lower, llm)
    else:
        grades = _grade_deterministic(docs, query_lower)

    return {
        "doc_grades": grades,
        "all_docs_relevant": all(grades),
    }


def _grade_with_llm(docs: list[dict], query: str, llm: Any) -> list[bool]:
    from langchain_core.messages import HumanMessage, SystemMessage
    grades = []
    system = SystemMessage(content=(
        "You are a cybersecurity relevance grader. "
        "Answer ONLY 'yes' or 'no' — is the document relevant to the query?"
    ))
    for doc in docs:
        human = HumanMessage(content=(
            f"Query: {query}\n\nDocument narrative: {doc.get('narrative', '')[:400]}"
        ))
        try:
            response = llm.invoke([system, human])
            text = (response.content if hasattr(response, "content") else str(response)).strip().lower()
            grades.append(text.startswith("yes"))
        except Exception:
            grades.append(True)  # fail-open para no bloquear el flujo por error de LLM
    return grades


def _grade_deterministic(docs: list[dict], query: str) -> list[bool]:
    query_words = set(query.split())
    query_words.update(kw for kw in _RELEVANCE_KEYWORDS if kw in query)
    grades = []
    for doc in docs:
        text = (doc.get("narrative", "") + " " + " ".join(doc.get("ttp_tags", []))).lower()
        overlap = sum(1 for w in query_words if w in text)
        grades.append(overlap >= 1 or doc.get("score", 0.0) >= 0.5)
    return grades


# ── Nodo 3: Reescritura de consulta ──────────────────────────────────────────

def rewrite_query_node(
    state: HermesState,
    llm: Optional[Any] = None,
) -> dict:
    """
    Reformula la consulta cuando los documentos recuperados no son relevantes.

    Con LLM: pide una reformulación semánticamente equivalente pero más precisa.
    Sin LLM: añade términos de contexto derivados de los TTPs y la IP origen.
    """
    original = state["query"]

    if llm is not None:
        new_query = _rewrite_with_llm(original, state, llm)
    else:
        new_query = _rewrite_deterministic(original, state)

    return {"query": new_query}


def _rewrite_with_llm(query: str, state: HermesState, llm: Any) -> str:
    from langchain_core.messages import HumanMessage, SystemMessage
    system = SystemMessage(content=(
        "You are a cybersecurity analyst. Rewrite the query to be more specific "
        "and likely to retrieve relevant threat intelligence episodes. "
        "Reply with ONLY the new query, no explanation."
    ))
    human = HumanMessage(content=(
        f"Original query: {query}\n"
        f"Source IP: {state.get('source_ip', 'unknown')}\n"
        "Rewrite to retrieve more relevant security episodes."
    ))
    try:
        response = llm.invoke([system, human])
        text = (response.content if hasattr(response, "content") else str(response)).strip()
        return text if text else query
    except Exception:
        return query


def _rewrite_deterministic(query: str, state: HermesState) -> str:
    enrichments = []
    ip = state.get("source_ip", "")
    if ip:
        enrichments.append(f"ip:{ip}")
    attck = state.get("attck_suggestions", [])
    if attck:
        enrichments.append(" ".join(attck[:3]))
    suffix = " " + " ".join(enrichments) if enrichments else " lateral movement credential"
    return query + suffix


# ── Nodo 4: Generación de hipótesis ──────────────────────────────────────────

def generate_node(
    state: HermesState,
    attck_graph: ATTCKGraph,
    llm: Optional[Any] = None,
    max_hypotheses: int = 3,
) -> dict:
    """
    Genera hipótesis de ataque a partir de documentos recuperados y el grafo ATT&CK.

    El LLM solo produce texto explicativo; nunca toma decisiones de autorización.
    """
    docs = state.get("retrieved_docs", [])
    doc_grades = state.get("doc_grades", [True] * len(docs))

    # Solo usar docs relevantes
    relevant_docs = [d for d, g in zip(docs, doc_grades) if g]

    # Expandir TTPs desde el grafo ATT&CK
    observed_ttps = _extract_ttps(relevant_docs)
    attck_suggestions = attck_graph.expand_hypothesis(observed_ttps, max_candidates=5)

    if llm is not None:
        texts = _generate_with_llm(state, relevant_docs, attck_suggestions, llm, max_hypotheses)
    else:
        texts = _generate_deterministic(state, relevant_docs, attck_suggestions, max_hypotheses)

    return {
        "hypothesis_texts": texts,
        "attck_suggestions": attck_suggestions,
    }


def _extract_ttps(docs: list[dict]) -> list[str]:
    ttps = []
    for doc in docs:
        ttps.extend(doc.get("ttp_tags", []))
    return list(dict.fromkeys(ttps))   # deduplicado manteniendo orden


def _generate_with_llm(
    state: HermesState,
    docs: list[dict],
    attck_suggestions: list[str],
    llm: Any,
    max_hypotheses: int,
) -> list[str]:
    from langchain_core.messages import HumanMessage, SystemMessage

    doc_summaries = "\n".join(
        f"- [{i+1}] {d.get('narrative', '')[:200]}" for i, d in enumerate(docs[:5])
    )
    system = SystemMessage(content=(
        "You are a threat hunting analyst. Generate concise threat hypotheses. "
        f"Produce exactly {max_hypotheses} hypotheses, one per line, numbered. "
        "Base them on the evidence provided. Do NOT include recommendations, only hypotheses."
    ))
    human = HumanMessage(content=(
        f"Source IP: {state.get('source_ip', 'unknown')}\n"
        f"Relevant ATT&CK techniques to investigate: {', '.join(attck_suggestions)}\n\n"
        f"Supporting episodes:\n{doc_summaries}\n\n"
        f"Generate {max_hypotheses} threat hypotheses:"
    ))
    try:
        response = llm.invoke([system, human])
        text = response.content if hasattr(response, "content") else str(response)
        lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
        # limpiar numeración
        hypotheses = []
        for line in lines:
            for prefix in ["1.", "2.", "3.", "4.", "5.", "- ", "* "]:
                if line.startswith(prefix):
                    line = line[len(prefix):].strip()
                    break
            if line:
                hypotheses.append(line)
        return hypotheses[:max_hypotheses] or [_fallback_hypothesis(state, attck_suggestions)]
    except Exception:
        return _generate_deterministic(state, docs, attck_suggestions, max_hypotheses)


def _generate_deterministic(
    state: HermesState,
    docs: list[dict],
    attck_suggestions: list[str],
    max_hypotheses: int,
) -> list[str]:
    ip = state.get("source_ip", "unknown")
    ttps_str = ", ".join(attck_suggestions[:3]) if attck_suggestions else "unknown TTPs"
    templates = [
        f"Possible lateral movement from {ip} using techniques: {ttps_str}",
        f"Credential access attempt from {ip} — pattern matches historical episode",
        f"Command-and-control communication from {ip} consistent with {ttps_str}",
    ]
    if docs:
        first_narrative = docs[0].get("narrative", "")[:80]
        templates[0] = f"Hypothesis based on similar episode: {first_narrative} — source: {ip}"
    return templates[:max_hypotheses]


def _fallback_hypothesis(state: HermesState, attck_suggestions: list[str]) -> str:
    ip = state.get("source_ip", "unknown")
    ttps = ", ".join(attck_suggestions[:2]) if attck_suggestions else "unknown"
    return f"Anomalous activity from {ip} consistent with {ttps}"


# ── Nodo 5: Verificación (double-check) ──────────────────────────────────────

def verify_node(
    state: HermesState,
    llm: Optional[Any] = None,
) -> dict:
    """
    Verifica que las hipótesis generadas estén respaldadas por evidencia concreta.

    Detecta alucinaciones: hipótesis sin ninguna conexión con los documentos recuperados.
    """
    hypotheses = state.get("hypothesis_texts", [])
    docs = state.get("retrieved_docs", [])

    if not hypotheses:
        return {"hypothesis_grounded": False, "verify_retries": state.get("verify_retries", 0) + 1}

    if llm is not None:
        grounded = _verify_with_llm(hypotheses, docs, llm)
    else:
        grounded = _verify_deterministic(hypotheses, docs)

    return {
        "hypothesis_grounded": grounded,
        "verify_retries": state.get("verify_retries", 0) + 1,
    }


def _verify_with_llm(hypotheses: list[str], docs: list[dict], llm: Any) -> bool:
    from langchain_core.messages import HumanMessage, SystemMessage

    doc_text = "\n".join(f"- {d.get('narrative', '')[:150]}" for d in docs[:4])
    hyp_text = "\n".join(f"- {h}" for h in hypotheses)
    system = SystemMessage(content=(
        "You are a cybersecurity verifier. Check if the hypotheses are grounded "
        "in the provided evidence. Answer ONLY 'yes' (grounded) or 'no' (hallucination)."
    ))
    human = HumanMessage(content=(
        f"Evidence:\n{doc_text}\n\nHypotheses:\n{hyp_text}\n\n"
        "Are these hypotheses grounded in the evidence?"
    ))
    try:
        response = llm.invoke([system, human])
        text = (response.content if hasattr(response, "content") else str(response)).strip().lower()
        return text.startswith("yes")
    except Exception:
        return True  # fail-open: no penalizar por error de LLM


def _verify_deterministic(hypotheses: list[str], docs: list[dict]) -> bool:
    """Comprueba solapamiento léxico entre hipótesis y documentos."""
    if not docs:
        return len(hypotheses) > 0   # sin docs, aceptamos hipótesis del fallback

    all_doc_text = " ".join(
        d.get("narrative", "") + " " + " ".join(d.get("ttp_tags", []))
        for d in docs
    ).lower()

    for hypothesis in hypotheses:
        words = set(w for w in hypothesis.lower().split() if len(w) > 3)
        overlap = sum(1 for w in words if w in all_doc_text)
        if overlap >= 2:
            return True

    # si hay docs y TTPs sugeridos también cuenta como anclaje
    attck = hypotheses[0].lower() if hypotheses else ""
    return any(kw in attck for kw in _RELEVANCE_KEYWORDS)


# ── Nodo 6: Budget checkpoint ─────────────────────────────────────────────────

def budget_checkpoint_node(
    state: HermesState,
    max_iterations: int,
) -> dict:
    """Marca budget_exhausted si se alcanzó el límite de iteraciones."""
    exhausted = state.get("iterations", 0) >= max_iterations
    return {"budget_exhausted": exhausted}

"""Estado LangGraph para el agente Hermes CRAG."""

from __future__ import annotations

from typing import Optional
from typing_extensions import TypedDict


class HermesState(TypedDict):
    """
    Estado mutable que fluye por el grafo LangGraph de Hermes.

    Todos los campos son primitivas o listas de primitivas para garantizar
    serialización y compatibilidad con checkpointers de LangGraph.
    """
    # Entrada inicial
    query: str                        # consulta de búsqueda derivada del evento
    source_ip: str                    # IP origen del evento
    event_features: list[float]       # vector de Centinela

    # Recuperación (Ornith)
    retrieved_docs: list[dict]        # [{id, narrative, ttp_tags, score}, ...]
    doc_grades: list[bool]            # relevancia de cada doc
    all_docs_relevant: bool           # True si todos los docs son relevantes

    # Generación + verificación
    hypothesis_texts: list[str]       # hipótesis generadas por el LLM (o fallback)
    attck_suggestions: list[str]      # TTPs sugeridos por el grafo ATT&CK
    hypothesis_grounded: bool         # True si la hipótesis tiene respaldo en docs

    # Control de flujo y budget
    iterations: int                   # nº de ciclos retrieve → grade → (rewrite?)
    verify_retries: int               # nº de reintentos de verificación
    budget_exhausted: bool            # True si se alcanzó max_iterations

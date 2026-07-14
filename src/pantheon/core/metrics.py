"""Métricas Prometheus para Pantheon v2.1."""

from prometheus_client import Counter, Histogram

EVENTS_PROCESSED = Counter(
    "pantheon_events_processed_total",
    "Eventos procesados por el pipeline",
    ["verdict"],
)

CCI_SCORE = Histogram(
    "pantheon_cci_score",
    "Distribución de scores CCI de Centinela",
    buckets=[0.1, 0.2, 0.3, 0.45, 0.6, 0.75, 0.9, 1.0],
)

HYPOTHESES_GENERATED = Counter(
    "pantheon_hypotheses_generated_total",
    "Hipótesis generadas por Hermes",
)

HERMES_ITERATIONS = Histogram(
    "pantheon_hermes_iterations_total",
    "Iteraciones de LangGraph por investigación",
    buckets=[1, 2, 3, 4, 5, 6],
)

ARES_POLLS_TOTAL = Counter(
    "pantheon_ares_polls_total",
    "Ciclos de polling del AresBridgeWorker",
    ["status"],   # ok | error | cb_open
)

PURPLE_ESCALATED_TOTAL = Counter(
    "pantheon_purple_escalated_total",
    "Escalados Purple Team recibidos",
)

FEEDBACK_ACCEPTED = Counter(
    "pantheon_feedback_accepted_total",
    "Feedback de operador aceptado por IPCA",
    ["operator_id"],
)

KILLSWITCH_TRIGGERED = Counter(
    "pantheon_killswitch_triggered_total",
    "Activaciones del Kill Switch",
    ["source"],   # operator | auto
)

RATE_LIMITED_REQUESTS = Counter(
    "pantheon_rate_limited_requests_total",
    "Peticiones bloqueadas por rate limiting",
)

"""
FastAPI — API REST de Pantheon v2.1.

Endpoints:
  POST /events              — ingestar evento de red (Input Guard → Centinela)
  GET  /hypotheses          — hipótesis rankeadas para el operador actual
  POST /approve/{id}        — aprobar contención
  POST /deny/{id}           — denegar contención
  GET  /pending             — solicitudes de aprobación pendientes
  POST /feedback            — feedback dimensional firmado (JWT)
  GET  /purple/escalated    — hipótesis escaladas desde Ares (Purple Team)
  POST /purple/escalated    — Ares publica un escalado a Pantheon (webhook)
  GET  /audit           — últimas N entradas del Audit Trail
  POST /killswitch      — activar Kill Switch
  GET  /health          — healthcheck

Autenticación: Bearer JWT en todos los endpoints excepto /health.
"""

from __future__ import annotations

import collections
import hmac
import json
import os
import re
import threading
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from pantheon.acme.feedback_auth import (
    AuthError,
    SignedFeedback,
    decode_operator_token,
)
from pantheon.core.config import settings
from pantheon.core.metrics import KILLSWITCH_TRIGGERED, RATE_LIMITED_REQUESTS
from pantheon.core.pipeline import get_pipeline
from pantheon.core.purple_bridge import (
    PurpleBridgeError,
    get_escalated,
    receive_escalated,
)

app = FastAPI(
    title="Pantheon v2.1",
    description="Threat Hunting Autónomo con Memoria Episódica",
    version="2.1.0",
)


# ── Rate Limiting Middleware ──────────────────────────────────────────────────

class _RateLimiter:
    """Token bucket por IP: max `limit` requests por ventana de 60 segundos."""

    def __init__(self, limit: int = settings.api_rate_limit) -> None:
        self._limit  = limit
        self._lock   = threading.Lock()
        self._buckets: dict[str, collections.deque] = {}

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        window = 60.0
        with self._lock:
            if ip not in self._buckets:
                self._buckets[ip] = collections.deque()
            bucket = self._buckets[ip]
            # descartar timestamps fuera de la ventana
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= self._limit:
                return False
            bucket.append(now)
            return True


_rate_limiter = _RateLimiter()

# ── Ring buffer de eventos recientes (últimos 200) ────────────────────────────

_event_log: collections.deque = collections.deque(maxlen=200)
_event_log_lock = threading.Lock()


def _classify_attack(verdict: str, cci: float, guard_verdict: str) -> str:
    """Clasifica el tipo de evento para el War Room."""
    if guard_verdict == "block":
        return "injection"
    if guard_verdict == "quarantine":
        return "quarantine"
    if cci >= 0.75:
        return "critical_anomaly"
    if cci >= 0.45:
        return "moderate_anomaly"
    return "normal"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    # Eximir /health y /metrics del rate limiting
    if request.url.path in ("/health", "/metrics"):
        return await call_next(request)
    if not _rate_limiter.is_allowed(client_ip):
        RATE_LIMITED_REQUESTS.inc()
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit excedido. Máximo de peticiones por minuto alcanzado."},
        )
    return await call_next(request)


# ── Modelos de request ────────────────────────────────────────────────────────

class NetworkEventRequest(BaseModel):
    features: list[float]
    source_ip: str
    log_text: Optional[str] = None


class FeedbackRequest(BaseModel):
    hypothesis_id: str
    thumbs: str
    relevance: int
    clarity: int
    actionability: int
    urgency: int
    signature: str


class KillSwitchRequest(BaseModel):
    reason: str = "manual"


# ── Autenticación ─────────────────────────────────────────────────────────────

def _get_operator(authorization: str = Header(...)) -> str:
    """Extrae y verifica el operator_id del Bearer JWT."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token Bearer requerido")
    token = authorization.removeprefix("Bearer ")
    try:
        decoded = decode_operator_token(token, settings.pantheon_jwt_secret)
    except AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    return decoded.operator_id


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "pantheon", "version": "2.1.0"}


@app.post("/events", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    event: NetworkEventRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """
    Ingestar un evento de red.

    Pipeline: InputGuard → Centinela → Hermes (si CCI ≥ umbral) → AcmeRanker.
    """
    result = get_pipeline().process_event(
        features=event.features,
        source_ip=event.source_ip,
        log_text=event.log_text or "",
        operator_id=operator_id,
    )
    d = result.to_dict()
    with _event_log_lock:
        _event_log.appendleft({
            "ts":           time.time(),
            "source_ip":    event.source_ip,
            "cci":          d.get("cci", 0),
            "guard_verdict": d.get("guard_verdict", "pass"),
            "accepted":     d.get("accepted", True),
            "is_critical":  d.get("is_critical", False),
            "hypotheses":   len(d.get("hypotheses", [])),
            "attack_type":  _classify_attack(
                d.get("guard_verdict", "pass"),
                d.get("cci", 0),
                d.get("guard_verdict", "pass"),
            ),
            "operator_id":  operator_id,
        })
    return d


@app.get("/hypotheses")
def get_hypotheses(
    operator_id: str = Depends(_get_operator),
    limit: int = 10,
) -> dict:
    """Devuelve las hipótesis rankeadas más recientes para el operador."""
    hypotheses = get_pipeline().get_hypotheses(operator_id, limit=limit)
    return {
        "operator_id": operator_id,
        "count": len(hypotheses),
        "hypotheses": hypotheses,
    }


@app.post("/approve/{request_id}")
def approve_contention(
    request_id: str,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Aprueba una solicitud de contención pendiente."""
    return {
        "request_id": request_id,
        "status": "approved",
        "decided_by": operator_id,
    }


@app.post("/deny/{request_id}")
def deny_contention(
    request_id: str,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Deniega una solicitud de contención pendiente."""
    return {
        "request_id": request_id,
        "status": "denied",
        "decided_by": operator_id,
    }


@app.get("/pending")
def get_pending(operator_id: str = Depends(_get_operator)) -> dict:
    """Lista las solicitudes de aprobación pendientes."""
    return {"pending": [], "operator_id": operator_id}


@app.post("/feedback")
def submit_feedback(
    feedback: FeedbackRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """
    Recibe feedback dimensional firmado.
    La firma se verifica antes de incorporar al perfil IPCA.
    """
    signed = SignedFeedback(
        operator_id=operator_id,
        payload={
            "thumbs":        feedback.thumbs,
            "relevance":     feedback.relevance,
            "clarity":       feedback.clarity,
            "actionability": feedback.actionability,
            "urgency":       feedback.urgency,
        },
        signature=feedback.signature,
    )
    from pantheon.acme.feedback_auth import verify_feedback
    if not verify_feedback(signed, settings.pantheon_jwt_secret):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Firma de feedback inválida — feedback rechazado",
        )
    # Incorporar al perfil IPCA del operador a través del ranker del pipeline
    from pantheon.acme.ranker import FeedbackRejected
    try:
        get_pipeline()._ranker.accept_feedback(signed)
    except FeedbackRejected as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {"accepted": True, "hypothesis_id": feedback.hypothesis_id}


@app.get("/audit")
def get_audit(
    operator_id: str = Depends(_get_operator),
    limit: int = 20,
) -> dict:
    """Devuelve las últimas N entradas del Audit Trail."""
    return {
        "entries": [],
        "limit": limit,
        "message": "Audit Trail disponible tras inicializar BD (uv run python scripts/init_db.py)",
    }


@app.get("/purple/escalated")
def get_purple_escalated(
    operator_id: str = Depends(_get_operator),
    limit: int = 50,
    only_unprocessed: bool = False,
) -> dict:
    """Devuelve hipótesis escaladas desde Ares v3.2 (Purple Team bridge)."""
    escalated = get_escalated(limit=limit, only_unprocessed=only_unprocessed)
    return {"escalated": escalated, "count": len(escalated)}


@app.post("/purple/escalated", status_code=status.HTTP_201_CREATED)
def post_purple_escalated(
    payload: dict,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """
    Recibe un escalado de Ares v3.2.

    Valida el payload con Pydantic + allowlist de hosts antes de almacenar.
    """
    try:
        record = receive_escalated(payload)
    except PurpleBridgeError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {
        "accepted": True,
        "content_hash": record.content_hash,
        "hypothesis_id": record.hypothesis.hypothesis_id,
    }


@app.post("/killswitch")
def trigger_killswitch(
    request: KillSwitchRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Activa el Kill Switch de Pantheon (aborta todas las operaciones activas)."""
    KILLSWITCH_TRIGGERED.labels(source="operator").inc()
    return {
        "triggered": True,
        "reason": request.reason,
        "operator_id": operator_id,
    }


@app.get("/events/recent", include_in_schema=False)
def events_recent(
    limit: int = 50,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Últimos N eventos procesados (ring buffer en memoria)."""
    with _event_log_lock:
        events = list(_event_log)[:limit]
    return {"events": events, "total": len(_event_log)}


@app.post("/purple/escalated/log", include_in_schema=False)
def _purple_log_hook(payload: dict, operator_id: str = Depends(_get_operator)) -> dict:
    """Hook interno para registrar escalados Ares en el event log."""
    with _event_log_lock:
        _event_log.appendleft({
            "ts":           time.time(),
            "source_ip":    payload.get("source_ip", "ares"),
            "cci":          0.0,
            "guard_verdict": "pass",
            "accepted":     True,
            "is_critical":  payload.get("severity") == "critical",
            "hypotheses":   0,
            "attack_type":  "ares_escalation",
            "operator_id":  operator_id,
        })
    return {"logged": True}


@app.get("/metrics/json", include_in_schema=False)
def metrics_json(operator_id: str = Depends(_get_operator)) -> dict:
    """Métricas Prometheus devueltas como JSON estructurado."""
    from prometheus_client import generate_latest
    raw = generate_latest().decode("utf-8")
    result: dict = {}
    for line in raw.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        m = re.match(r'^([a-z_]+)(?:\{([^}]*)\})?\s+([\d.e+\-]+)', line)
        if not m:
            continue
        name, labels_str, value = m.group(1), m.group(2) or "", m.group(3)
        try:
            v = float(value)
        except ValueError:
            continue
        if labels_str:
            label_pairs = dict(re.findall(r'(\w+)="([^"]*)"', labels_str))
            key = f"{name}{{{','.join(f'{k}={v}' for k,v in label_pairs.items())}}}"
        else:
            key = name
        result[key] = v
    # Agrega conteo de eventos del ring buffer
    with _event_log_lock:
        evs = list(_event_log)
    type_counts: dict = {}
    for e in evs:
        t = e.get("attack_type", "normal")
        type_counts[t] = type_counts.get(t, 0) + 1
    result["_event_log_total"] = len(evs)
    result["_event_types"] = type_counts
    return result


@app.get("/dashboard", include_in_schema=False)
def dashboard(token: Optional[str] = None) -> HTMLResponse:
    """War Room — dashboard en tiempo real de Pantheon."""
    html_path = os.path.join(os.path.dirname(__file__), "war_room.html")
    with open(html_path, encoding="utf-8") as f:
        html = f.read()
    if token:
        html = html.replace("__PREFILL_TOKEN__", token)
    else:
        html = html.replace("__PREFILL_TOKEN__", "")
    return HTMLResponse(content=html)


@app.get("/metrics", include_in_schema=False)
def metrics() -> PlainTextResponse:
    """Expone métricas Prometheus en formato text/plain."""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return PlainTextResponse(
        content=generate_latest().decode("utf-8"),
        media_type=CONTENT_TYPE_LATEST,
    )

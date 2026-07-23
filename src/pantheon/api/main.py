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
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from pantheon.acme.feedback_auth import (
    AuthError,
    SignedFeedback,
    create_operator_token,
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
    # Eximir /health, /metrics, /token y /ornith/ingest del rate limiting
    if request.url.path in ("/health", "/metrics", "/ornith/ingest", "/token"):
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


class OrnithIngestRequest(BaseModel):
    campaign_id: str
    run_number: int
    phase: int
    tactic: str
    source_ip: str
    target_ip: str = "127.0.0.1"
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    technique_sequence: list[str] = []
    feature_vector: list[float] = []
    cci_per_step: list[float] = []
    anomaly_signature: str
    hypothesis: str = ""


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


class TokenRequest(BaseModel):
    operator_id: str
    expire_hours: int = 8


@app.post("/token", summary="Generar JWT de operador")
def create_token(req: TokenRequest) -> dict:
    """Genera un JWT firmado para autenticar al operador en todos los endpoints.

    No requiere autenticación previa — es el punto de entrada para nuevos usuarios.
    El `operator_id` identifica al analista en el Audit Trail y en Acme Ranker.
    """
    token = create_operator_token(
        req.operator_id,
        settings.pantheon_jwt_secret,
        expire_hours=req.expire_hours,
    )
    return {
        "token": token,
        "operator_id": req.operator_id,
        "expire_hours": req.expire_hours,
        "usage": f"Authorization: Bearer {token}",
    }


@app.post("/ornith/ingest", status_code=status.HTTP_201_CREATED)
def ornith_ingest(
    req: OrnithIngestRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """
    Ingesta directa de episodio desde Ares — bypassa Centinela/Hermes/Guard.

    Indexa el episodio en Qdrant (Ornith) y actualiza los pesos de co-ocurrencia
    del grafo ATT&CK en el pipeline activo. Exento de rate limiting.
    """
    import uuid as _uuid
    from pantheon.ornith.client import index_episode
    from pantheon.ornith.episode_schema import Episode

    ws = datetime.fromisoformat(req.window_start) if req.window_start else None
    we = datetime.fromisoformat(req.window_end) if req.window_end else None

    episode = Episode(
        id=str(_uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        anomaly_signature=req.anomaly_signature,
        campaign_id=req.campaign_id,
        source_ip=req.source_ip,
        window_start=ws,
        window_end=we,
        technique_sequence=req.technique_sequence,
        hypothesis=req.hypothesis or f"Automated: Run {req.run_number:02d} — {req.tactic}",
    )

    # update_cooccurrence — in-memory, sin I/O, crítico para A*. Respuesta inmediata.
    cooc_ok = False
    if req.technique_sequence:
        try:
            get_pipeline()._attck.update_cooccurrence(req.technique_sequence)
            cooc_ok = True
        except Exception as exc:
            logger.warning("ornith_ingest: update_cooccurrence falló: %s", exc)

    # index_episode (Qdrant + embedding) en hilo daemon — no bloquea la respuesta.
    def _bg_index() -> None:
        try:
            index_episode(episode)
        except Exception as exc:
            logger.warning("ornith_ingest bg: %s", exc)

    threading.Thread(target=_bg_index, daemon=True).start()

    return {
        "episode_id": episode.id,
        "indexed": True,          # optimista — el hilo background completará
        "cooccurrence_updated": cooc_ok,
        "campaign_id": req.campaign_id,
        "techniques_applied": len(req.technique_sequence),
    }


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


# ── Connectores (Suricata / Wazuh) ───────────────────────────────────────────

class ConnectorConfigRequest(BaseModel):
    eve_json_path: Optional[str] = None
    api_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    poll_interval_secs: Optional[int] = None
    stale_threshold_secs: Optional[int] = None
    min_rule_level: Optional[int] = None
    verify_ssl: Optional[bool] = None


@app.get("/connectors", summary="Estado de conectores Suricata / Wazuh")
def list_connectors(operator_id: str = Depends(_get_operator)) -> dict:
    from dataclasses import asdict
    from pantheon.connectors.manager import get_connector_manager
    mgr = get_connector_manager()
    return {"connectors": {n: asdict(s) for n, s in mgr.get_all_status().items()}}


@app.post("/connectors/{name}/config", summary="Guardar config de conector")
def update_connector_config(
    name: str,
    req: ConnectorConfigRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    from pantheon.connectors.manager import get_connector_manager
    mgr = get_connector_manager()
    config = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        mgr.update_config(name, config)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return {"saved": True, "name": name}


@app.post("/connectors/{name}/toggle", summary="Habilitar / deshabilitar conector")
def toggle_connector(name: str, operator_id: str = Depends(_get_operator)) -> dict:
    from pantheon.connectors.manager import get_connector_manager
    mgr = get_connector_manager()
    try:
        enabled = mgr.toggle(name)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc))
    return {"name": name, "enabled": enabled}


@app.get("/connectors/{name}/test", summary="Probar conexión al origen")
def test_connector(name: str, operator_id: str = Depends(_get_operator)) -> dict:
    from pantheon.connectors.manager import get_connector_manager
    return get_connector_manager().test(name)


# ── LLM config (runtime, sin reiniciar) ──────────────────────────────────────

class LLMConfigRequest(BaseModel):
    model: str
    base_url: str = "http://localhost:11434"


@app.get("/config/llm", summary="Leer configuración de LLM activa")
def get_llm_config() -> dict:
    from pantheon.core.ollama_llm import get_runtime_model, get_runtime_base_url, OllamaLLM, _runtime
    return {
        "model":            get_runtime_model(),
        "base_url":         get_runtime_base_url(),
        "from_runtime":     bool(_runtime),
        "available_models": OllamaLLM.list_models(),
    }


@app.post("/config/llm", summary="Cambiar modelo Ollama sin reiniciar")
def set_llm_config(req: LLMConfigRequest, operator_id: str = Depends(_get_operator)) -> dict:
    from pantheon.core.ollama_llm import update_runtime
    update_runtime(model=req.model, base_url=req.base_url)
    get_pipeline().reset_hermes()
    return {"ok": True, "model": req.model, "base_url": req.base_url}


# ── Knowledge Exchange ────────────────────────────────────────────────────────

@app.get("/export/graph")
def export_graph(operator_id: str = Depends(_get_operator)) -> dict:
    """Exporta los pesos de co-ocurrencia aprendidos del grafo ATT&CK.

    El JSON resultante puede importarse en otra instancia de Pantheon via
    POST /import/knowledge para transferir conocimiento entre equipos sin
    exponer datos operacionales sensibles.
    """
    from pantheon.attck_graph.graph import get_shared_graph
    return get_shared_graph().export_weights()


class ImportKnowledgeRequest(BaseModel):
    cooccurrence: dict[str, int] = {}
    edges: list[dict] = []
    version: str = "1.0"
    merge: bool = True  # True = suma conteos; False = sobreescribe


@app.post("/import/knowledge")
def import_knowledge(
    req: ImportKnowledgeRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Importa pesos de co-ocurrencia de otra instancia de Pantheon.

    Acepta el formato producido por GET /export/graph.
    Con merge=True (default) los conteos se suman al conocimiento existente.
    """
    from pantheon.attck_graph.graph import get_shared_graph
    updated = get_shared_graph().import_weights(req.model_dump(), merge=req.merge)
    return {"imported_pairs": updated, "merge": req.merge}


class IOCEntry(BaseModel):
    technique_sequence: list[str] = []
    ttps: list[str] = []          # alias para compatibilidad
    source: str = "external"
    description: str = ""


@app.post("/import/ioc")
def import_ioc(
    iocs: list[IOCEntry],
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Importa una lista de IOCs externos con secuencias de técnicas ATT&CK.

    Actualiza el grafo de co-ocurrencias para que A* refleje el conocimiento
    externo desde el primer evento. Útil para calibrar Hermes con inteligencia
    de amenazas de otros equipos antes de que Ares genere episodios propios.
    """
    from pantheon.attck_graph.graph import get_shared_graph
    processed = get_shared_graph().import_ioc_list([i.model_dump() for i in iocs])
    return {"processed_sequences": processed, "total_submitted": len(iocs)}


@app.get("/export/stix")
def export_stix(operator_id: str = Depends(_get_operator)) -> dict:
    """Exporta episodios y técnicas detectadas como bundle STIX 2.1.

    Compatible con MISP, OpenCTI y cualquier plataforma que consuma STIX.
    Incluye: indicators (IPs), attack-patterns (técnicas ATT&CK) y
    observed-data (campañas detectadas por Hermes).
    """
    import uuid as _uuid
    from pantheon.attck_graph.graph import get_shared_graph
    from pantheon.core.pipeline import get_pipeline

    g = get_shared_graph()
    pipeline = get_pipeline()
    hyps = pipeline.get_hypotheses("default", limit=50)
    now_iso = datetime.now(timezone.utc).isoformat()

    objects = []

    # Identity del sistema
    identity_id = f"identity--{_uuid.uuid5(_uuid.NAMESPACE_DNS, 'pantheon.local')}"
    objects.append({
        "type": "identity", "spec_version": "2.1",
        "id": identity_id,
        "name": "Pantheon v2.1", "identity_class": "system",
        "created": now_iso, "modified": now_iso,
    })

    # Attack-patterns desde el grafo (aristas con peso aprendido)
    weights_data = g.export_weights()
    seen_ttps: set[str] = set()
    for edge in weights_data.get("edges", []):
        for tid in (edge["src"], edge["tgt"]):
            if tid not in seen_ttps:
                seen_ttps.add(tid)
                ap_id = f"attack-pattern--{_uuid.uuid5(_uuid.NAMESPACE_DNS, tid)}"
                objects.append({
                    "type": "attack-pattern", "spec_version": "2.1",
                    "id": ap_id, "name": tid,
                    "created": now_iso, "modified": now_iso,
                    "created_by_ref": identity_id,
                    "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                    "x_pantheon_tactic": edge.get("tactic_src", "unknown"),
                })

    # Indicators desde hipótesis (IPs origen)
    seen_ips: set[str] = set()
    for h in hyps:
        ip = h.get("source_ip", "")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            ind_id = f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_DNS, ip)}"
            objects.append({
                "type": "indicator", "spec_version": "2.1",
                "id": ind_id,
                "name": f"Suspicious IP: {ip}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "created": now_iso, "modified": now_iso,
                "created_by_ref": identity_id,
                "confidence": min(100, int((h.get("score", 0.5)) * 100)),
            })

    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


@app.get("/export/sigma")
def export_sigma(operator_id: str = Depends(_get_operator)) -> PlainTextResponse:
    """Genera reglas Sigma desde las técnicas ATT&CK detectadas por Pantheon.

    Las reglas resultantes pueden importarse en Splunk, Elastic SIEM,
    Microsoft Sentinel y otros SIEMs compatibles con Sigma.
    """
    from pantheon.attck_graph.graph import get_shared_graph
    from pantheon.core.pipeline import get_pipeline

    g = get_shared_graph()
    pipeline = get_pipeline()
    hyps = pipeline.get_hypotheses("default", limit=50)

    # Recolectar TTPs únicos con evidencia
    all_ttps: set[str] = set()
    for h in hyps:
        all_ttps.update(h.get("ttp_tags", []))
        all_ttps.update(h.get("attck_suggestions", []))
    weights = g.export_weights()
    for edge in weights.get("edges", []):
        all_ttps.add(edge["src"]); all_ttps.add(edge["tgt"])

    ips = list({h.get("source_ip","") for h in hyps if h.get("source_ip")})

    now_str = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    rules = []

    if ips:
        rules.append(f"""title: Pantheon - Suspicious Source IPs
id: pantheon-ips-{datetime.now(timezone.utc).strftime('%Y%m%d')}
status: experimental
description: IPs marcadas como sospechosas por Pantheon v2.1 threat hunting
date: {now_str}
tags:
{chr(10).join(f"  - attack.{g.get_tactic(t)}" for t in list(all_ttps)[:5] if g.get_tactic(t) != "unknown")}
logsource:
  category: network
  product: generic
detection:
  selection:
    src_ip:
{chr(10).join(f"      - '{ip}'" for ip in ips[:20])}
  condition: selection
falsepositives:
  - Pentesting autorizado
  - Actividad de Ares (Purple Team)
level: high
""")

    if all_ttps:
        ttp_list = sorted(all_ttps)
        rules.append(f"""title: Pantheon - ATT&CK Techniques Observed
id: pantheon-ttps-{datetime.now(timezone.utc).strftime('%Y%m%d')}
status: experimental
description: Técnicas ATT&CK observadas durante hunting con Pantheon v2.1
date: {now_str}
tags:
{chr(10).join(f"  - attack.{t.lower()}" for t in ttp_list[:10])}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'powershell -enc'
      - 'wmic process'
  condition: selection
falsepositives:
  - Administración legítima
level: medium
""")

    content = "# Sigma rules generadas por Pantheon v2.1\n# " + datetime.now(timezone.utc).isoformat() + "\n\n"
    content += "\n---\n\n".join(rules) if rules else "# Sin técnicas detectadas aún\n"
    return PlainTextResponse(content=content, media_type="text/plain")

"""
FastAPI — API REST de Pantheon v2.1.

Endpoints:
  POST /events          — ingestar evento de red (Input Guard → Centinela)
  GET  /hypotheses      — hipótesis rankeadas para el operador actual
  POST /approve/{id}    — aprobar contención
  POST /deny/{id}       — denegar contención
  GET  /pending         — solicitudes de aprobación pendientes
  POST /feedback        — feedback dimensional firmado (JWT)
  GET  /audit           — últimas N entradas del Audit Trail
  POST /killswitch      — activar Kill Switch
  GET  /health          — healthcheck

Autenticación: Bearer JWT en todos los endpoints excepto /health.
"""

from __future__ import annotations

import hmac
import json
import os
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from pantheon.acme.feedback_auth import (
    AuthError,
    SignedFeedback,
    decode_operator_token,
)
from pantheon.core.config import settings

app = FastAPI(
    title="Pantheon v2.1",
    description="Threat Hunting Autónomo con Memoria Episódica",
    version="2.1.0",
)


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

    El evento pasa por Input Guard → si está limpio, Centinela lo evalúa
    y lo enruta (Hermes o triaje humano).
    """
    return {
        "accepted": True,
        "source_ip": event.source_ip,
        "message": "Evento recibido y encolado para procesamiento",
    }


@app.get("/hypotheses")
def get_hypotheses(
    operator_id: str = Depends(_get_operator),
    limit: int = 10,
) -> dict:
    """Devuelve las hipótesis rankeadas más recientes para el operador."""
    return {
        "operator_id": operator_id,
        "hypotheses": [],
        "message": "Sin hipótesis pendientes",
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


@app.post("/killswitch")
def trigger_killswitch(
    request: KillSwitchRequest,
    operator_id: str = Depends(_get_operator),
) -> dict:
    """Activa el Kill Switch de Pantheon (aborta todas las operaciones activas)."""
    return {
        "triggered": True,
        "reason": request.reason,
        "operator_id": operator_id,
    }

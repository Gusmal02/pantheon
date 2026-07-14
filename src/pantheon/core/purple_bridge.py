"""
Purple Team Bridge — integración bidireccional Pantheon ↔ Ares v3.2.

Pantheon consume los escalados de Ares (ejercicios ofensivos confirmados como
activos reales) para enriquecer el contexto de caza. El bridge expone:

  GET /purple/escalated — devuelve hipótesis escaladas desde Ares
  POST /purple/escalated — Ares publica un escalado a Pantheon (webhook)

Separación de responsabilidades:
  - Ares genera el escalado y lo envía a Pantheon via POST.
  - Pantheon lo valida y lo incorpora a la cola de Hermes.
  - La decisión de si una hipótesis escalada merece respuesta la toma el operador.

Seguridad:
  - El payload de escalado se valida con Pydantic antes de procesarse.
  - La fuente del escalado (ares_source) se valida contra una allowlist de hosts.
  - El LLM nunca interviene en la validación.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from pydantic import BaseModel, field_validator

from pantheon.core.config import settings

# Allowlist de hosts Ares autorizados a publicar escalados
_ALLOWED_ARES_HOSTS = {
    "localhost",
    "127.0.0.1",
    "ares-api",           # nombre de servicio Docker
    "ares.internal",      # nombre interno de red
}

# Patrón de hypothesis_id: alfanumérico + guiones, máx 64 chars
_HYPOTHESIS_ID_RE = re.compile(r"^[a-zA-Z0-9\-_]{1,64}$")

# Almacén en memoria de escalados recibidos (en producción: PostgreSQL)
_escalated_store: list[dict] = []


# ── Modelos Pydantic ──────────────────────────────────────────────────────────

class EscalatedHypothesis(BaseModel):
    """Payload de un escalado recibido desde Ares v3.2."""

    hypothesis_id: str
    source_ip: str
    ttp_tags: list[str] = []
    severity: str = "moderate"
    narrative: str
    ares_source: str        # host de Ares que publica el escalado
    timestamp: float = field(default_factory=time.time)

    @field_validator("hypothesis_id")
    @classmethod
    def validate_hypothesis_id(cls, v: str) -> str:
        if not _HYPOTHESIS_ID_RE.match(v):
            raise ValueError(f"hypothesis_id inválido: {v!r}")
        return v

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"source_ip inválida: {v!r}") from exc
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "moderate", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity debe ser uno de {allowed}, got {v!r}")
        return v.lower()

    @field_validator("ares_source")
    @classmethod
    def validate_ares_source(cls, v: str) -> str:
        host = v.split(":")[0].strip()   # eliminar puerto si viene con host:port
        if host not in _ALLOWED_ARES_HOSTS:
            raise ValueError(f"ares_source no autorizado: {v!r}")
        return v

    @field_validator("narrative")
    @classmethod
    def validate_narrative(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("narrative no puede estar vacío")
        if len(v) > 2000:
            raise ValueError("narrative demasiado largo (máx 2000 chars)")
        return v.strip()


@dataclass
class EscalatedRecord:
    """Registro interno de un escalado procesado."""
    hypothesis: EscalatedHypothesis
    received_at: float = field(default_factory=time.time)
    content_hash: str = ""
    processed: bool = False

    def __post_init__(self):
        if not self.content_hash:
            raw = f"{self.hypothesis.hypothesis_id}:{self.hypothesis.source_ip}:{self.hypothesis.narrative}"
            self.content_hash = hashlib.sha256(raw.encode()).hexdigest()


# ── Lógica del bridge ─────────────────────────────────────────────────────────

class PurpleBridgeError(ValueError):
    """Error de validación en el Purple Bridge."""


def receive_escalated(payload: dict) -> EscalatedRecord:
    """
    Recibe y valida un escalado de Ares.

    Valida con Pydantic antes de almacenar. Rechaza duplicados por content_hash.

    Args:
        payload — dict con los campos de EscalatedHypothesis

    Returns:
        EscalatedRecord con el escalado procesado.

    Raises:
        PurpleBridgeError si la validación falla o es duplicado.
    """
    try:
        hypothesis = EscalatedHypothesis(**payload)
    except Exception as exc:
        raise PurpleBridgeError(f"Payload de escalado inválido: {exc}") from exc

    record = EscalatedRecord(hypothesis=hypothesis)

    # Evitar duplicados por hash de contenido
    existing_hashes = {r["content_hash"] for r in _escalated_store}
    if record.content_hash in existing_hashes:
        raise PurpleBridgeError(f"Escalado duplicado detectado: {record.content_hash[:16]}…")

    _escalated_store.append({
        "hypothesis_id": hypothesis.hypothesis_id,
        "source_ip":     hypothesis.source_ip,
        "ttp_tags":      hypothesis.ttp_tags,
        "severity":      hypothesis.severity,
        "narrative":     hypothesis.narrative,
        "ares_source":   hypothesis.ares_source,
        "timestamp":     hypothesis.timestamp,
        "received_at":   record.received_at,
        "content_hash":  record.content_hash,
        "processed":     False,
    })
    return record


def get_escalated(limit: int = 50, only_unprocessed: bool = False) -> list[dict]:
    """
    Devuelve los escalados recibidos desde Ares.

    Args:
        limit           — máximo de registros a devolver
        only_unprocessed — si True, solo los no procesados por Hermes

    Returns:
        Lista de dicts con los escalados.
    """
    results = _escalated_store
    if only_unprocessed:
        results = [r for r in results if not r["processed"]]
    return results[-limit:]


def mark_processed(content_hash: str) -> bool:
    """Marca un escalado como procesado por Hermes."""
    for record in _escalated_store:
        if record["content_hash"] == content_hash:
            record["processed"] = True
            return True
    return False


def clear_store() -> None:
    """Limpia el store en memoria. Solo para tests."""
    _escalated_store.clear()

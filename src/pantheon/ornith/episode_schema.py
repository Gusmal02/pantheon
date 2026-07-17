"""Esquema formal de un episodio de threat hunting en Ornith."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class TTPTag(str, Enum):
    """Subconjunto inicial de tácticas MITRE ATT&CK relevantes para el proyecto.
    Se amplía conforme se ingieren más episodios."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral-movement"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command-and-control"


class Episode(BaseModel):
    """Un episodio de investigación: cómo un analista (o Hermes) razonó
    sobre una anomalía hasta llegar a una hipótesis."""

    id: str = Field(..., description="UUID del episodio")
    timestamp: datetime = Field(..., description="Cuándo ocurrió la investigación")

    anomaly_signature: str = Field(
        ..., description="Resumen de la anomalía detectada por Centinela + ventana temporal"
    )
    campaign_id: str | None = Field(
        default=None,
        description="ID de run de Ares o clúster HDBSCAN que agrupa eventos de la misma campaña",
    )

    # ── Campos de sesión (granulado de campaña) ───────────────────────────────
    source_ip: str | None = Field(
        default=None,
        description="IP origen del evento que inició la investigación",
    )
    window_start: datetime | None = Field(
        default=None,
        description="Inicio de la ventana temporal del episodio (primer evento de la campaña)",
    )
    window_end: datetime | None = Field(
        default=None,
        description="Fin de la ventana temporal del episodio (último evento de la campaña)",
    )
    technique_sequence: list[str] = Field(
        default_factory=list,
        description=(
            "Secuencia ordenada de IDs de técnicas ATT&CK observadas en la campaña "
            "(ej. ['T1046', 'T1021', 'T1135']). Usada para la heurística de co-ocurrencia en A*."
        ),
    )

    hypothesis: str = Field(..., description="Hipótesis de investigación generada o documentada")
    evidence_retrieved: list[str] = Field(
        default_factory=list, description="IDs de documentos/episodios usados como evidencia"
    )

    ttp_tags: list[TTPTag] = Field(
        default_factory=list,
        description="Tácticas MITRE ATT&CK (nivel táctico, no técnico). Ver technique_sequence para IDs de técnicas.",
    )
    iocs_extraidos: list[str] = Field(
        default_factory=list, description="IPs, hashes, dominios, CVE-IDs detectados (NER/regex)"
    )

    playbook_applied: str | None = Field(default=None)
    analyst_feedback: str | None = Field(
        default=None, description="thumbs up/down + nota del analista, si existe"
    )

    model_config = ConfigDict(use_enum_values=True)

    @property
    def window_duration_seconds(self) -> float | None:
        """Duración de la ventana temporal en segundos, o None si no está definida."""
        if self.window_start and self.window_end:
            return (self.window_end - self.window_start).total_seconds()
        return None
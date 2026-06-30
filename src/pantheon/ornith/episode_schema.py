"""Esquema formal de un episodio de threat hunting en Ornith."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


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
        default=None, description="ID de clúster HDBSCAN, si la anomalía pertenece a una campaña"
    )

    hypothesis: str = Field(..., description="Hipótesis de investigación generada o documentada")
    evidence_retrieved: list[str] = Field(
        default_factory=list, description="IDs de documentos/episodios usados como evidencia"
    )

    ttp_tags: list[TTPTag] = Field(default_factory=list)
    iocs_extraidos: list[str] = Field(
        default_factory=list, description="IPs, hashes, dominios, CVE-IDs detectados (NER/regex)"
    )

    playbook_applied: str | None = Field(default=None)
    analyst_feedback: str | None = Field(
        default=None, description="thumbs up/down + nota del analista, si existe"
    )

    class Config:
        use_enum_values = True
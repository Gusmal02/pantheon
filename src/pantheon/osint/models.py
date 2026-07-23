"""Modelos de datos para el enrichment OSINT."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatContext(BaseModel):
    """Contexto de amenaza agregado de fuentes OSINT externas para una IP."""

    ip: str
    threat_score: float = Field(0.0, ge=0.0, le=1.0)
    is_known_malicious: bool = False
    active_campaign: bool = False          # presente en blocklist activo (Feodo, etc.)
    categories: list[str] = Field(default_factory=list)   # ["botnet_c2", "port_scan", ...]
    country_code: str = ""                 # "CN", "RU", ""
    asn_org: str = ""                      # "AS4134 CHINANET"
    total_reports: int = 0                 # reportes de abuso acumulados
    sources_hit: list[str] = Field(default_factory=list)  # fuentes que devolvieron datos
    cached: bool = False

    def summary(self) -> str:
        """Texto compacto para incluir en prompts de Hermes."""
        if not self.sources_hit:
            return f"[OSINT] {self.ip}: sin datos en fuentes externas"
        parts = [f"[OSINT] {self.ip}: score={self.threat_score:.2f}"]
        if self.is_known_malicious:
            parts.append("MALICIOSO")
        if self.active_campaign:
            parts.append("en blocklist activo")
        if self.categories:
            parts.append(f"cats={','.join(self.categories)}")
        if self.country_code:
            parts.append(f"país={self.country_code}")
        if self.asn_org:
            parts.append(f"ASN={self.asn_org}")
        if self.total_reports:
            parts.append(f"reportes={self.total_reports}")
        parts.append(f"fuentes={','.join(self.sources_hit)}")
        return " | ".join(parts)

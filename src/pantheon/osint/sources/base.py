"""Interfaz base para fuentes OSINT."""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseOsintSource(ABC):
    name: str = "base"

    @property
    def available(self) -> bool:
        """True si la fuente está configurada y lista para consultas."""
        return True

    @abstractmethod
    def lookup(self, ip: str) -> dict:
        """Consulta la fuente para la IP dada.

        Returns:
            Dict parcial con campos de ThreatContext. Vacío si no hay datos.
            Nunca lanza excepciones — el aggregator gestiona fallos.
        """
        ...

"""
Muralla — Playbook Guard determinista.

Valida que un playbook sea ejecutable según tres criterios:
  1. Hash SHA-256 registrado en la allowlist de playbooks curados.
  2. Parámetros válidos según el esquema Pydantic del playbook.
  3. Scope del entorno simulado: IP target en una red permitida,
     no es una IP excluida, acción en la lista de acciones permitidas.

El LLM nunca participa en esta decisión.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ValidationError, field_validator, model_validator

from pantheon.muralla.allowlist import PlaybookAllowlist, PlaybookMeta

_DEFAULT_SCOPE_PATH = Path("policy/sim_scope.json")


class PlaybookNotAllowed(RuntimeError):
    """El playbook no está en la allowlist o sus parámetros son inválidos."""


class ScopeViolation(RuntimeError):
    """La acción viola el scope del entorno simulado."""


class ValidationResult(str, Enum):
    ALLOWED   = "allowed"
    REJECTED  = "rejected"


@dataclass
class MurallaDecision:
    result: ValidationResult
    playbook_id: str
    reason: str
    playbook_meta: Optional[PlaybookMeta] = None


class SimScope:
    """Carga y valida el scope del entorno simulado."""

    def __init__(self, scope_data: dict) -> None:
        self._networks = [
            ipaddress.ip_network(net, strict=False)
            for net in scope_data.get("allowed_networks", [])
        ]
        self._excluded = {
            ipaddress.ip_address(ip)
            for ip in scope_data.get("excluded_ips", [])
        }
        self._allowed_actions = set(scope_data.get("allowed_playbook_actions", []))
        self._max_isolation_secs = scope_data.get("max_isolation_duration_secs", 3600)
        self._allowed_port_ranges = scope_data.get("allowed_port_ranges", [])

    @classmethod
    def from_json(cls, path: Path | str = _DEFAULT_SCOPE_PATH) -> "SimScope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    def is_ip_in_scope(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip in self._excluded:
            return False
        return any(ip in net for net in self._networks)

    def is_action_allowed(self, action: str) -> bool:
        return action in self._allowed_actions

    def is_port_allowed(self, port: int) -> bool:
        return any(
            r["from"] <= port <= r["to"] for r in self._allowed_port_ranges
        )

    @property
    def max_isolation_secs(self) -> int:
        return self._max_isolation_secs


class IsolateHostParams(BaseModel):
    target_ip: str
    duration_secs: int

    @field_validator("target_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"IP inválida: {v}") from exc
        return v

    @field_validator("duration_secs")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v < 60 or v > 3600:
            raise ValueError(f"duration_secs debe estar en [60, 3600], got {v}")
        return v


class BlockIpParams(BaseModel):
    target_ip: str
    direction: str
    duration_secs: int

    @field_validator("target_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"IP inválida: {v}") from exc
        return v

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: str) -> str:
        if v not in ("inbound", "outbound", "both"):
            raise ValueError(f"direction inválido: {v}")
        return v

    @field_validator("duration_secs")
    @classmethod
    def validate_duration(cls, v: int) -> int:
        if v < 60 or v > 86400:
            raise ValueError(f"duration_secs debe estar en [60, 86400], got {v}")
        return v


_PARAM_MODELS: dict[str, type[BaseModel]] = {
    "isolate_host": IsolateHostParams,
    "block_ip":     BlockIpParams,
}


class MurallaGuard:
    """
    Playbook Guard determinista.

    Valida un playbook antes de enviarlo a ejecución.
    Si cualquier check falla → MurallaDecision(result=REJECTED).
    El LLM nunca participa en esta decisión.

    Args:
        allowlist — PlaybookAllowlist cargada desde policy/curated_playbooks.json
        scope     — SimScope cargado desde policy/sim_scope.json
    """

    def __init__(self, allowlist: PlaybookAllowlist, scope: SimScope) -> None:
        self._allowlist = allowlist
        self._scope = scope

    def validate(
        self,
        playbook_hash: str,
        parameters: dict[str, Any],
    ) -> MurallaDecision:
        """
        Valida un playbook.

        Args:
            playbook_hash — SHA-256 del playbook (calculado por el War Room)
            parameters    — dict de parámetros del playbook

        Returns:
            MurallaDecision con result=ALLOWED o result=REJECTED.
        """
        meta = self._allowlist.lookup_by_hash(playbook_hash)
        if meta is None:
            return MurallaDecision(
                result=ValidationResult.REJECTED,
                playbook_id="unknown",
                reason=f"Hash {playbook_hash[:16]}… no registrado en la allowlist",
            )

        param_model = _PARAM_MODELS.get(meta.action)
        if param_model is not None:
            try:
                param_model(**parameters)
            except (ValidationError, TypeError) as exc:
                return MurallaDecision(
                    result=ValidationResult.REJECTED,
                    playbook_id=meta.id,
                    reason=f"Parámetros inválidos: {exc}",
                    playbook_meta=meta,
                )

        if not self._scope.is_action_allowed(meta.action):
            return MurallaDecision(
                result=ValidationResult.REJECTED,
                playbook_id=meta.id,
                reason=f"Acción '{meta.action}' no está en el scope del entorno simulado",
                playbook_meta=meta,
            )

        target_ip = parameters.get("target_ip")
        if target_ip and not self._scope.is_ip_in_scope(target_ip):
            return MurallaDecision(
                result=ValidationResult.REJECTED,
                playbook_id=meta.id,
                reason=f"IP {target_ip} fuera del scope o excluida",
                playbook_meta=meta,
            )

        return MurallaDecision(
            result=ValidationResult.ALLOWED,
            playbook_id=meta.id,
            reason="Validación OK",
            playbook_meta=meta,
        )

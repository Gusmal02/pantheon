"""
Operator Approval Gate para Pantheon — aprobación síncrona fail-closed.

Adaptado de Ares v3.2. Timeout más largo por defecto (threat hunting requiere
más tiempo de análisis que pentesting).

Flujo:
  1. ApprovalGate.request(action, risk_level, timeout) → bloquea
  2. La solicitud se almacena en Redis con TTL (auto-deny al expirar)
  3. El operador llama a approve(id) o deny(id) desde el War Room / API
  4. request() devuelve ApprovalRequest(status=APPROVED) o lanza ApprovalDenied

Fail-closed: timeout == denegado. El playbook NO se ejecuta sin aprobación.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

APPROVAL_KEY_PREFIX = "pantheon:approval:"
_POLL_INTERVAL = 0.25


class ApprovalStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    DENIED   = "denied"
    TIMEOUT  = "timeout"


@dataclass
class ApprovalRequest:
    request_id:   str
    action:       str
    target:       str
    risk_level:   str
    operator_id:  str
    created_at:   str
    timeout_secs: int
    status:       ApprovalStatus = ApprovalStatus.PENDING
    decided_at:   str = ""
    decided_by:   str = ""

    def to_dict(self) -> dict:
        return {
            "request_id":   self.request_id,
            "action":       self.action,
            "target":       self.target,
            "risk_level":   self.risk_level,
            "operator_id":  self.operator_id,
            "created_at":   self.created_at,
            "timeout_secs": self.timeout_secs,
            "status":       self.status.value,
            "decided_at":   self.decided_at,
            "decided_by":   self.decided_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalRequest":
        d = dict(data)
        d["status"] = ApprovalStatus(d.get("status", "pending"))
        return cls(**d)


class ApprovalDenied(RuntimeError):
    """La solicitud fue denegada o expiró (fail-closed)."""


class ApprovalGate:
    """
    Gate de aprobación Redis-backed para Pantheon.

    Args:
        redis_client  — cliente Redis
        audit_fn      — callable(request, status) para registrar en Audit Trail
        poll_interval — segundos entre polls
    """

    def __init__(
        self,
        redis_client,
        audit_fn: Optional[Callable[[ApprovalRequest, ApprovalStatus], None]] = None,
        poll_interval: float = _POLL_INTERVAL,
    ) -> None:
        self._redis   = redis_client
        self._audit   = audit_fn
        self._poll    = poll_interval

    def _key(self, request_id: str) -> str:
        return f"{APPROVAL_KEY_PREFIX}{request_id}"

    def request(
        self,
        action:      str,
        target:      str,
        risk_level:  str = "high",
        operator_id: str = "system",
        timeout:     Optional[int] = None,
    ) -> ApprovalRequest:
        """Solicita aprobación y BLOQUEA hasta decisión o timeout (fail-closed)."""
        from pantheon.core.config import settings
        timeout = timeout or settings.pantheon_approval_timeout_secs

        req = ApprovalRequest(
            request_id=str(uuid.uuid4()),
            action=action,
            target=target,
            risk_level=risk_level,
            operator_id=operator_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            timeout_secs=timeout,
        )
        self._store(req)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self._load(req.request_id)
            if current is None:
                req.status = ApprovalStatus.TIMEOUT
                self._call_audit(req, ApprovalStatus.TIMEOUT)
                raise ApprovalDenied(f"Aprobación {req.request_id} expiró (fail-closed)")

            if current.status == ApprovalStatus.APPROVED:
                self._call_audit(current, ApprovalStatus.APPROVED)
                return current

            if current.status == ApprovalStatus.DENIED:
                self._call_audit(current, ApprovalStatus.DENIED)
                raise ApprovalDenied(
                    f"Aprobación {req.request_id} denegada por {current.decided_by}"
                )
            time.sleep(self._poll)

        req.status = ApprovalStatus.TIMEOUT
        self._redis.delete(self._key(req.request_id))
        self._call_audit(req, ApprovalStatus.TIMEOUT)
        raise ApprovalDenied(f"Aprobación {req.request_id} timeout ({timeout}s) — denegada")

    def approve(self, request_id: str, decided_by: str = "operator") -> bool:
        return self._decide(request_id, ApprovalStatus.APPROVED, decided_by)

    def deny(self, request_id: str, decided_by: str = "operator") -> bool:
        return self._decide(request_id, ApprovalStatus.DENIED, decided_by)

    def get_pending(self) -> list[ApprovalRequest]:
        pending = []
        for key in self._redis.scan_iter(f"{APPROVAL_KEY_PREFIX}*"):
            req = self._load_from_key(key)
            if req and req.status == ApprovalStatus.PENDING:
                pending.append(req)
        return pending

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._load(request_id)

    def _store(self, req: ApprovalRequest) -> None:
        self._redis.setex(self._key(req.request_id), req.timeout_secs, json.dumps(req.to_dict()))

    def _load(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._load_from_key(self._key(request_id))

    def _load_from_key(self, key: str) -> Optional[ApprovalRequest]:
        raw = self._redis.get(key)
        if raw is None:
            return None
        data = json.loads(raw)
        return ApprovalRequest.from_dict(data)

    def _decide(self, request_id: str, status: ApprovalStatus, decided_by: str) -> bool:
        req = self._load(request_id)
        if req is None or req.status != ApprovalStatus.PENDING:
            return False
        req.status     = status
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = decided_by
        key = self._key(request_id)
        ttl = max(self._redis.ttl(key), 60)
        self._redis.setex(key, ttl, json.dumps(req.to_dict()))
        return True

    def _call_audit(self, req: ApprovalRequest, status: ApprovalStatus) -> None:
        if self._audit:
            try:
                self._audit(req, status)
            except Exception:
                pass

"""
WORM Replication — confirmación S3 síncrona.

Adaptado de Ares v3.2. La ejecución de la acción queda BLOQUEADA
hasta recibir ACK de S3. Si S3 no responde → WORMError → abort.

Variables de entorno:
  WORM_ENDPOINT     — URL del bucket S3-compatible
  WORM_TIMEOUT_SECS — timeout de confirmación (default 5s)
  WORM_ENABLED      — "1" para activar; "0" desactiva (dev/test)
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

_WORM_ENDPOINT = os.environ.get("WORM_ENDPOINT", "http://localhost:9000/pantheon-audit")
_WORM_TIMEOUT = int(os.environ.get("WORM_TIMEOUT_SECS", "5"))
_WORM_ENABLED = os.environ.get("WORM_ENABLED", "0") == "1"


@dataclass
class WORMReceipt:
    object_key: str
    etag: str
    confirmed: bool
    timestamp: str
    skipped: bool = False


class WORMError(RuntimeError):
    """S3 no confirmó el registro dentro del timeout."""


def _object_key(entry_id: str, session_id: str) -> str:
    return f"audit/{session_id}/{entry_id}.json"


def replicate_to_worm(
    entry_id: str,
    session_id: str,
    chain_hash: str,
    payload: dict,
    endpoint: str = _WORM_ENDPOINT,
    timeout: int = _WORM_TIMEOUT,
    enabled: bool = _WORM_ENABLED,
) -> WORMReceipt:
    """
    Replica un registro del Audit Trail a S3 WORM y espera confirmación síncrona.

    Returns:
        WORMReceipt con confirmed=True si S3 ACK fue recibido.

    Raises:
        WORMError — si S3 no responde o devuelve error.
    """
    ts = datetime.now(timezone.utc).isoformat()

    if not enabled:
        return WORMReceipt(
            object_key=_object_key(entry_id, session_id),
            etag="",
            confirmed=False,
            timestamp=ts,
            skipped=True,
        )

    key = _object_key(entry_id, session_id)
    body = json.dumps(
        {**payload, "chain_hash": chain_hash, "_replicated_at": ts},
        sort_keys=True,
    )

    try:
        resp = httpx.put(
            f"{endpoint}/{key}",
            content=body.encode(),
            headers={
                "Content-Type": "application/json",
                "x-amz-acl": "private",
                "Content-MD5": hashlib.md5(body.encode()).hexdigest(),
            },
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        raise WORMError(
            f"S3 WORM timeout ({timeout}s) para entry_id={entry_id}"
        ) from exc
    except httpx.RequestError as exc:
        raise WORMError(f"S3 WORM unreachable: {exc}") from exc

    if resp.status_code not in (200, 201, 204):
        raise WORMError(
            f"S3 WORM respondió {resp.status_code} para entry_id={entry_id}"
        )

    etag = resp.headers.get("ETag", "").strip('"')
    return WORMReceipt(
        object_key=key,
        etag=etag,
        confirmed=True,
        timestamp=ts,
    )

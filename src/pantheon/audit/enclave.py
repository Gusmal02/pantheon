"""
Pre-commit log append-only con HMAC-SHA256 y hash encadenado.

Adaptado de Ares v3.2 (src/common/enclave.py) para Pantheon.
Diferencia clave: esta clase NO se llama desde el path de negocio;
la invoca el worker del patrón Outbox (audit/worker.py) para garantizar
que el pre-commit log solo se escribe tras confirmar la transacción ACID.

Garantías:
  - Append-only: nunca sobreescribe líneas existentes.
  - Firma por línea: cada entrada incluye HMAC de su contenido.
  - chain_hash: SHA-256(action|timestamp|operator_id|nonce|chain_hash_prev)
  - fsync antes de retornar (garantiza escritura a disco).
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pantheon.core.config import settings

_ENCLAVE_KEY = os.environ.get("PANTHEON_ENCLAVE_KEY", settings.pantheon_enclave_key)
_LOG_PATH = settings.pantheon_enclave_log
_LOCK = threading.Lock()


@dataclass
class EnclaveEntry:
    entry_id: str
    action: str
    timestamp: str
    operator_id: str
    nonce: str
    chain_hash: str
    hmac_sig: str


def _sign(payload: str, key: str = _ENCLAVE_KEY) -> str:
    return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def verify_signature(entry: EnclaveEntry, key: str = _ENCLAVE_KEY) -> bool:
    payload = _entry_payload(entry)
    expected = _sign(payload, key)
    return hmac.compare_digest(expected, entry.hmac_sig)


def _entry_payload(entry: EnclaveEntry) -> str:
    return json.dumps({
        "entry_id":    entry.entry_id,
        "action":      entry.action,
        "timestamp":   entry.timestamp,
        "operator_id": entry.operator_id,
        "nonce":       entry.nonce,
        "chain_hash":  entry.chain_hash,
    }, sort_keys=True)


def compute_chain_hash(
    action: str,
    timestamp: str,
    operator_id: str,
    nonce: str,
    previous_hash: str,
) -> str:
    """chain_hash_n = SHA-256(action|timestamp|operator_id|nonce|chain_hash_{n-1})"""
    raw = f"{action}|{timestamp}|{operator_id}|{nonce}|{previous_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def genesis_hash(session_id: str) -> str:
    """Semilla del primer registro de sesión."""
    return hashlib.sha256(f"genesis:{session_id}".encode()).hexdigest()


class PreCommitLog:
    """
    Log append-only. El worker del Outbox lo invoca después de confirmar
    que el registro está en PostgreSQL con replicated=FALSE.

    Thread-safe mediante _LOCK global.
    """

    def __init__(
        self,
        session_id: str,
        log_path: Optional[Path] = None,
        enclave_key: Optional[str] = None,
    ):
        self._session_id = session_id
        self._log_path = log_path or _LOG_PATH
        self._key = enclave_key or _ENCLAVE_KEY
        self._last_hash = genesis_hash(session_id)
        self._last_hash = self._recover_last_hash() or self._last_hash

    def _recover_last_hash(self) -> Optional[str]:
        if not self._log_path.exists():
            return None
        last_chain = None
        try:
            with self._log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("session_id") == self._session_id:
                            last_chain = data.get("chain_hash")
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return None
        return last_chain

    def write(
        self,
        entry_id: str,
        action: str,
        operator_id: str,
        nonce: Optional[str] = None,
    ) -> EnclaveEntry:
        """
        Escribe una entrada al pre-commit log (append-only) con fsync.
        Solo llamar desde el worker del Outbox, no desde el path de negocio.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = nonce or secrets.token_hex(16)

        with _LOCK:
            chain_hash = compute_chain_hash(
                action=action,
                timestamp=timestamp,
                operator_id=operator_id,
                nonce=nonce,
                previous_hash=self._last_hash,
            )
            entry = EnclaveEntry(
                entry_id=entry_id,
                action=action,
                timestamp=timestamp,
                operator_id=operator_id,
                nonce=nonce,
                chain_hash=chain_hash,
                hmac_sig="",
            )
            entry.hmac_sig = _sign(_entry_payload(entry), self._key)

            record = {
                "session_id":  self._session_id,
                "entry_id":    entry_id,
                "action":      action,
                "timestamp":   timestamp,
                "operator_id": operator_id,
                "nonce":       nonce,
                "chain_hash":  chain_hash,
                "hmac_sig":    entry.hmac_sig,
            }

            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
                f.flush()
                os.fsync(f.fileno())

            self._last_hash = chain_hash

        return entry

    def verify_chain(self) -> tuple[bool, int]:
        """Verifica la integridad completa de la cadena para esta sesión."""
        if not self._log_path.exists():
            return True, 0

        prev_hash = genesis_hash(self._session_id)
        count = 0
        try:
            with self._log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    if data.get("session_id") != self._session_id:
                        continue
                    entry = EnclaveEntry(
                        **{k: data[k] for k in
                           ("entry_id", "action", "timestamp",
                            "operator_id", "nonce", "chain_hash", "hmac_sig")}
                    )
                    if not verify_signature(entry, self._key):
                        return False, count
                    expected = compute_chain_hash(
                        entry.action, entry.timestamp,
                        entry.operator_id, entry.nonce, prev_hash,
                    )
                    if expected != entry.chain_hash:
                        return False, count
                    prev_hash = entry.chain_hash
                    count += 1
        except (OSError, json.JSONDecodeError, KeyError):
            return False, count

        return True, count

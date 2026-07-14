"""
Autenticación JWT y firma de feedback para Acme Ranker.

El War Room autentica al analista con JWT. Cada payload de feedback
dimensional se firma con HMAC-SHA256 derivado del secreto JWT.
El backend verifica la firma antes de incorporar el feedback al perfil IPCA.

Sin firma válida → feedback rechazado (bloquea envenenamiento por suplantación).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class OperatorToken:
    operator_id: str
    exp: float       # Unix timestamp de expiración
    scope: list[str]


@dataclass
class SignedFeedback:
    operator_id: str
    payload: dict
    signature: str


class AuthError(RuntimeError):
    """Token inválido, expirado o firma no verificada."""


def _derive_feedback_key(jwt_secret: str, operator_id: str) -> str:
    """Clave HMAC para el feedback: SHA-256(jwt_secret + operator_id)."""
    return hashlib.sha256(f"{jwt_secret}:{operator_id}".encode()).hexdigest()


def sign_feedback(
    payload: dict[str, Any],
    operator_id: str,
    jwt_secret: str,
) -> SignedFeedback:
    """
    Firma un payload de feedback dimensional.

    Args:
        payload     — dict con thumbs, relevance, clarity, actionability, urgency
        operator_id — ID del analista (del token JWT)
        jwt_secret  — secreto JWT del sistema

    Returns:
        SignedFeedback con payload + firma HMAC.
    """
    canonical = json.dumps({**payload, "operator_id": operator_id}, sort_keys=True)
    key = _derive_feedback_key(jwt_secret, operator_id)
    signature = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return SignedFeedback(operator_id=operator_id, payload=payload, signature=signature)


def verify_feedback(signed: SignedFeedback, jwt_secret: str) -> bool:
    """
    Verifica la firma de un payload de feedback.

    Returns:
        True si la firma es válida; False en caso contrario.
    """
    canonical = json.dumps(
        {**signed.payload, "operator_id": signed.operator_id}, sort_keys=True
    )
    key = _derive_feedback_key(jwt_secret, signed.operator_id)
    expected = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signed.signature)


def create_operator_token(
    operator_id: str,
    jwt_secret: str,
    expire_hours: int = 1,
) -> str:
    """
    Crea un token JWT simplificado (HS256 sin librería externa).

    En producción usar python-jose con RS256.
    Para MVP: token = base64(header).base64(payload).HMAC(header.payload)
    """
    import base64
    now = time.time()
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_dict = {
        "sub": operator_id,
        "exp": now + expire_hours * 3600,
        "scope": ["feedback", "approve"],
        "iat": now,
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_dict).encode()
    ).rstrip(b"=").decode()
    signing_input = f"{header}.{payload_b64}"
    sig = hmac.new(
        jwt_secret.encode(), signing_input.encode(), hashlib.sha256
    ).hexdigest()
    sig_b64 = base64.urlsafe_b64encode(sig.encode()).rstrip(b"=").decode()
    return f"{signing_input}.{sig_b64}"


def decode_operator_token(token: str, jwt_secret: str) -> OperatorToken:
    """
    Decodifica y verifica un token de operador.

    Raises:
        AuthError si el token es inválido o expirado.
    """
    import base64

    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("Token malformado")

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}"

    # verificar firma
    expected_sig = hmac.new(
        jwt_secret.encode(), signing_input.encode(), hashlib.sha256
    ).hexdigest()
    expected_b64 = base64.urlsafe_b64encode(expected_sig.encode()).rstrip(b"=").decode()
    if not hmac.compare_digest(expected_b64, sig_b64):
        raise AuthError("Firma JWT inválida")

    # decodificar payload
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception as exc:
        raise AuthError(f"Payload JWT indecodificable: {exc}") from exc

    # verificar expiración
    if payload.get("exp", 0) < time.time():
        raise AuthError("Token expirado")

    return OperatorToken(
        operator_id=payload["sub"],
        exp=payload["exp"],
        scope=payload.get("scope", []),
    )

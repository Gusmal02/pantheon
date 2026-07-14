"""
Input Guard — pipeline completo de detección de inyección adversarial.

Pipeline:
  1. Clasificador primario (regex/heurísticas) → clean / suspicious / ambiguous
  2. Si SUSPICIOUS → bloquear directamente (sin gastar LLM)
  3. Si AMBIGUOUS → registrar en circuit breaker
       - CB ABIERTO  → modo contingencia: enviar a cuarentena sin LLM
       - CB CERRADO  → verificación LLM secundaria (stub en MVP)
  4. Si CLEAN → pasar al pipeline principal

La verificación LLM secundaria es un stub documentado: en MVP verifica
usando heurísticas adicionales. En producción se reemplaza por una llamada
a un LLM pequeño (ej. Ollama con phi-3-mini).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from pantheon.guards.circuit_breaker import CircuitBreaker
from pantheon.guards.classifier import ClassificationResult, LogLabel, classify_log


class GuardVerdict(str, Enum):
    PASS          = "pass"           # log limpio, continúa al pipeline
    BLOCK         = "block"          # inyección confirmada, rechazar
    QUARANTINE    = "quarantine"     # modo contingencia: cuarentena para triaje humano
    NEEDS_REVIEW  = "needs_review"   # ambiguo pero CB cerrado: LLM lo revisó y pasó


@dataclass
class GuardResult:
    verdict: GuardVerdict
    log_text: str
    label: LogLabel
    reason: str
    circuit_breaker_open: bool = False
    matched_pattern: Optional[str] = None


@dataclass
class QuarantineEntry:
    log_text: str
    source_ip: Optional[str]
    matched_pattern: Optional[str]
    reason: str = "Triaje Manual por Saturación"


class InputGuard:
    """
    Guard de entrada para Pantheon.

    Args:
        circuit_breaker — instancia de CircuitBreaker (inyectable)
        llm_verifier    — callable(log_text) → bool (True = limpio).
                          Si es None, se usa la heurística de fallback.
        on_quarantine   — callback opcional para notificar cuarentenas
    """

    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        llm_verifier: Optional[Callable[[str], bool]] = None,
        on_quarantine: Optional[Callable[[QuarantineEntry], None]] = None,
    ) -> None:
        from pantheon.core.config import settings
        self._cb = circuit_breaker or CircuitBreaker(
            rate_limit=settings.input_guard_rate_limit,
            cooldown_secs=settings.input_guard_cb_cooldown_secs,
        )
        self._llm_verifier   = llm_verifier or self._fallback_verifier
        self._on_quarantine  = on_quarantine
        self._quarantine_buf: list[QuarantineEntry] = []

    def process(self, log_text: str, source_ip: Optional[str] = None) -> GuardResult:
        """
        Procesa un log de entrada.

        Returns:
            GuardResult con el veredicto y razón.
        """
        classification = classify_log(log_text)

        if classification.label == LogLabel.CLEAN:
            return GuardResult(
                verdict=GuardVerdict.PASS,
                log_text=log_text,
                label=LogLabel.CLEAN,
                reason="Clasificador primario: limpio",
            )

        if classification.label == LogLabel.SUSPICIOUS:
            return GuardResult(
                verdict=GuardVerdict.BLOCK,
                log_text=log_text,
                label=LogLabel.SUSPICIOUS,
                reason=f"Inyección adversarial detectada: {classification.matched_pattern}",
                matched_pattern=classification.matched_pattern,
            )

        # AMBIGUOUS
        self._cb.record_ambiguous()

        if self._cb.is_open:
            entry = QuarantineEntry(
                log_text=log_text,
                source_ip=source_ip,
                matched_pattern=classification.matched_pattern,
            )
            self._quarantine_buf.append(entry)
            if self._on_quarantine:
                self._on_quarantine(entry)

            return GuardResult(
                verdict=GuardVerdict.QUARANTINE,
                log_text=log_text,
                label=LogLabel.AMBIGUOUS,
                reason="Circuit breaker abierto: log enviado a cuarentena para triaje humano",
                circuit_breaker_open=True,
                matched_pattern=classification.matched_pattern,
            )

        # CB cerrado → verificación secundaria
        is_clean = self._llm_verifier(log_text)
        if is_clean:
            return GuardResult(
                verdict=GuardVerdict.NEEDS_REVIEW,
                log_text=log_text,
                label=LogLabel.AMBIGUOUS,
                reason="Ambiguo pero verificador secundario lo aprobó",
                matched_pattern=classification.matched_pattern,
            )

        return GuardResult(
            verdict=GuardVerdict.BLOCK,
            log_text=log_text,
            label=LogLabel.AMBIGUOUS,
            reason=f"Verificador secundario confirmó inyección adversarial",
            matched_pattern=classification.matched_pattern,
        )

    def flush_quarantine(self) -> list[QuarantineEntry]:
        """Devuelve y vacía el buffer de cuarentena."""
        buf = list(self._quarantine_buf)
        self._quarantine_buf.clear()
        return buf

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return self._cb

    @staticmethod
    def _fallback_verifier(log_text: str) -> bool:
        """
        Verificador secundario heurístico (stub para MVP).
        Aprueba si el log no contiene instrucciones directas de rol.
        En producción: llamada a LLM pequeño local.
        """
        suspicious_tokens = [
            "you are now", "your new role", "pretend to be",
            "as an ai without", "bypass your"
        ]
        lower = log_text.lower()
        return not any(tok in lower for tok in suspicious_tokens)

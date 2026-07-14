"""
Clasificador de logs para el Input Guard.

Pipeline primario: reglas léxicas (regex + heurísticas).
Los logs se clasifican como:
  - clean      — sin indicios de inyección adversarial
  - suspicious — patrones de inyección claros → bloquear directamente
  - ambiguous  — posible inyección, requiere verificación secundaria

No se usa spaCy para el clasificador primario porque los patrones de
prompt injection son estructurales (marcadores de rol, instrucciones
directas al LLM) — regex es más rápido y predecible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# Patrones que indican inyección adversarial clara
_SUSPICIOUS_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(your|all)\s+(instructions?|rules?|guidelines?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(?:evil|uncensored|unrestricted|jailbreak)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:if\s+)?(?:DAN|an?\s+AI\s+without\s+restrictions?)", re.IGNORECASE),
    re.compile(r"<\s*/?system\s*>", re.IGNORECASE),          # etiquetas de rol
    re.compile(r"\[INST\]|\[/INST\]|\[ASSISTANT\]"),         # tokens de instrucción LLM
    re.compile(r"###\s*(System|Human|Assistant)\s*:", re.IGNORECASE),
    re.compile(r"OVERRIDE\s+SAFETY", re.IGNORECASE),
]

# Patrones ambiguos (posiblemente inyección, requieren verificación)
_AMBIGUOUS_PATTERNS: list[re.Pattern] = [
    re.compile(r"forget\s+(what|everything|all)\s+you", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+you\s+(will|must|should)", re.IGNORECASE),
    re.compile(r"your\s+(real|true|actual)\s+(purpose|goal|task)", re.IGNORECASE),
    re.compile(r"(reveal|show|print|output)\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"translate\s+the\s+(following|above)\s+to\s+\w+\s+and\s+then", re.IGNORECASE),
]


class LogLabel(str, Enum):
    CLEAN      = "clean"
    SUSPICIOUS = "suspicious"
    AMBIGUOUS  = "ambiguous"


@dataclass
class ClassificationResult:
    label: LogLabel
    matched_pattern: str | None = None
    confidence: float = 1.0


def classify_log(log_text: str) -> ClassificationResult:
    """
    Clasifica un log de entrada.

    Returns:
        ClassificationResult con label CLEAN, SUSPICIOUS o AMBIGUOUS.
    """
    for pattern in _SUSPICIOUS_PATTERNS:
        m = pattern.search(log_text)
        if m:
            return ClassificationResult(
                label=LogLabel.SUSPICIOUS,
                matched_pattern=pattern.pattern,
                confidence=0.95,
            )

    for pattern in _AMBIGUOUS_PATTERNS:
        m = pattern.search(log_text)
        if m:
            return ClassificationResult(
                label=LogLabel.AMBIGUOUS,
                matched_pattern=pattern.pattern,
                confidence=0.70,
            )

    return ClassificationResult(label=LogLabel.CLEAN, confidence=1.0)

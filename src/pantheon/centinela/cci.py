"""
Índice de Confianza Compuesto (CCI) de Centinela.

CCI combina tres señales para reducir falsos positivos antes de enviar
un evento a Hermes:

  P_anomaly : score del Isolation Forest (normalizado a [0, 1]).
              Cuanto más alto, más anómalo.

  D_centroid: distancia al centroide del clúster de ataque más cercano.
              Normalizada: 0 = justo en el centroide, 1 = muy lejos.
              Si está lejos de todos los ataques conocidos, confianza baja.

  C_temp    : consistencia temporal — fracción de eventos similares del
              mismo host en la última ventana (default 1 hora). [0, 1]

Formula:
  CCI = w1 * P_anomaly + w2 * (1 - D_centroid_norm) + w3 * C_temp

Umbrales (configurables en Settings):
  < cci_ambiguous_threshold → escalar a triaje humano directo
  >= cci_critical_threshold → prioridad máxima; aplica playbook de emergencia
                              si el analista no actúa a tiempo
"""

from dataclasses import dataclass
from enum import Enum


class CCIOutcome(str, Enum):
    LOW_CONFIDENCE = "low_confidence"   # < ambiguous_threshold → triaje humano
    MODERATE       = "moderate"         # entre los dos umbrales → pasa a Hermes
    CRITICAL       = "critical"         # >= critical_threshold → máxima prioridad


@dataclass
class CCIResult:
    cci: float
    p_anomaly: float
    d_centroid_norm: float
    c_temp: float
    outcome: CCIOutcome
    source_ip: str | None = None


# pesos por defecto (no negociables sin validación; deben sumar 1.0)
_W1 = 0.50  # anomaly score
_W2 = 0.30  # cercanía al centroide
_W3 = 0.20  # consistencia temporal


def compute_cci(
    p_anomaly: float,
    d_centroid_norm: float,
    c_temp: float,
    ambiguous_threshold: float = 0.45,
    critical_threshold: float = 0.75,
    w1: float = _W1,
    w2: float = _W2,
    w3: float = _W3,
    source_ip: str | None = None,
) -> CCIResult:
    """
    Calcula el CCI y determina el outcome para el evento.

    Args:
        p_anomaly         — anomaly score del Isolation Forest, en [0, 1]
        d_centroid_norm   — distancia normalizada al centroide de ataque, en [0, 1]
        c_temp            — consistencia temporal, en [0, 1]
        ambiguous_threshold — umbral inferior; por debajo → triaje humano
        critical_threshold  — umbral superior; por encima → prioridad crítica
    """
    p_anomaly = max(0.0, min(1.0, p_anomaly))
    d_centroid_norm = max(0.0, min(1.0, d_centroid_norm))
    c_temp = max(0.0, min(1.0, c_temp))

    cci = w1 * p_anomaly + w2 * (1.0 - d_centroid_norm) + w3 * c_temp

    if cci < ambiguous_threshold:
        outcome = CCIOutcome.LOW_CONFIDENCE
    elif cci >= critical_threshold:
        outcome = CCIOutcome.CRITICAL
    else:
        outcome = CCIOutcome.MODERATE

    return CCIResult(
        cci=round(cci, 4),
        p_anomaly=p_anomaly,
        d_centroid_norm=d_centroid_norm,
        c_temp=c_temp,
        outcome=outcome,
        source_ip=source_ip,
    )

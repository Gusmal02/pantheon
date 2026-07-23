"""MCP tools para Hermes — consultas contextuales a conectores activos.

Hermes llama estas funciones durante una investigación para enriquecer hipótesis
con datos en tiempo real de Suricata y Wazuh.
"""
from __future__ import annotations

from typing import Any


def query_suricata(
    ip: str | None = None,
    hours: float = 1.0,
    signature_contains: str | None = None,
) -> list[dict]:
    """Retorna alertas recientes de Suricata filtradas por IP o firma."""
    from pantheon.connectors.manager import get_connector_manager
    mgr = get_connector_manager()
    conn = mgr.get("suricata")
    if conn is None or not mgr.is_enabled("suricata"):
        return []
    return conn.recent_alerts(hours=hours, ip=ip, signature_contains=signature_contains)  # type: ignore[attr-defined]


def query_wazuh(
    host: str | None = None,
    hours: float = 1.0,
    rule_level_min: int = 5,
) -> list[dict]:
    """Retorna alertas recientes de Wazuh filtradas por host o nivel de regla."""
    from pantheon.connectors.manager import get_connector_manager
    mgr = get_connector_manager()
    conn = mgr.get("wazuh")
    if conn is None or not mgr.is_enabled("wazuh"):
        return []
    return conn.recent_alerts(hours=hours, host=host, rule_level_min=rule_level_min)  # type: ignore[attr-defined]


def query_osint(ip: str) -> dict:
    """Consulta threat intelligence externa (Feodo Tracker + AbuseIPDB) para una IP.

    Feodo Tracker funciona sin API key (botnet C2 blocklist).
    AbuseIPDB requiere ABUSEIPDB_API_KEY en .env (plan gratuito disponible).
    Los resultados se cachean 1 hora en memoria.
    """
    from pantheon.osint.aggregator import get_osint_aggregator
    ctx = get_osint_aggregator().enrich(ip)
    return ctx.model_dump()


# ── Registro de herramientas ──────────────────────────────────────────────────
# Cada entrada tiene: fn, description, params — suficiente para que Hermes
# genere prompts de enriquecimiento o para exponer como MCP server en el futuro.

MCP_TOOLS: dict[str, dict] = {
    "query_suricata": {
        "fn": query_suricata,
        "description": "Query recent Suricata EVE JSON alerts by source/dest IP or signature substring",
        "params": {
            "ip": "str | None — filter by source or destination IP",
            "hours": "float = 1.0 — look back window in hours",
            "signature_contains": "str | None — filter by signature substring",
        },
    },
    "query_wazuh": {
        "fn": query_wazuh,
        "description": "Query recent Wazuh alerts by agent IP/hostname or minimum rule level",
        "params": {
            "host": "str | None — filter by agent IP or name",
            "hours": "float = 1.0 — look back window in hours",
            "rule_level_min": "int = 5 — minimum Wazuh rule level (0-15)",
        },
    },
    "query_osint": {
        "fn": query_osint,
        "description": (
            "Query external threat intelligence for an IP address. "
            "Checks Feodo Tracker botnet C2 blocklist (no key required) and "
            "AbuseIPDB reputation score (requires ABUSEIPDB_API_KEY). "
            "Results cached 1h in memory."
        ),
        "params": {
            "ip": "str — IP address to enrich with external threat intel",
        },
    },
}


def call_tool(name: str, **kwargs: Any) -> Any:
    """Llama una MCP tool por nombre. Raises ValueError si no existe."""
    tool = MCP_TOOLS.get(name)
    if tool is None:
        raise ValueError(f"MCP tool desconocida: {name}")
    return tool["fn"](**kwargs)


def enrich_hypothesis(source_ips: list[str], hours: float = 2.0) -> str:
    """Enriquece una hipótesis con contexto de conectores activos y OSINT externo.

    Llamada por Hermes durante la fase de investigación. Retorna texto
    con evidencia de Suricata, Wazuh y threat intel externa (Feodo/AbuseIPDB).
    No lanza excepciones — retorna string vacío si no hay datos.
    """
    parts: list[str] = []
    for ip in source_ips[:3]:
        try:
            alerts = query_suricata(ip=ip, hours=hours)
            if alerts:
                sigs = ", ".join(a["signature"][:50] for a in alerts[:3] if a.get("signature"))
                parts.append(f"Suricata [{ip}]: {len(alerts)} alerts — {sigs}")
        except Exception:
            pass
        try:
            events = query_wazuh(host=ip, hours=hours)
            if events:
                descs = ", ".join(e["rule_description"][:50] for e in events[:3] if e.get("rule_description"))
                parts.append(f"Wazuh [{ip}]: {len(events)} events — {descs}")
        except Exception:
            pass
        try:
            from pantheon.osint.aggregator import get_osint_aggregator
            ctx = get_osint_aggregator().enrich(ip)
            if ctx.sources_hit:
                parts.append(ctx.summary())
        except Exception:
            pass
    return "\n".join(parts)

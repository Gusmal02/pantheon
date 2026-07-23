"""Fuente OSINT: AbuseIPDB v2 — reputación de IPs por abuso.

Requiere API key gratuita (1 000 req/día en free plan).
Docs: https://www.abuseipdb.com/api/v2/check
"""
from __future__ import annotations

import logging

import httpx

from pantheon.osint.sources.base import BaseOsintSource

logger = logging.getLogger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_MAX_AGE_DAYS = 30


class AbuseIPDBSource(BaseOsintSource):
    """Consulta AbuseIPDB para obtener confidence score y metadatos de una IP."""

    name = "abuseipdb"

    def __init__(self, api_key: str = "", timeout: int = 5) -> None:
        self._api_key = api_key
        self._timeout = timeout

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def lookup(self, ip: str) -> dict:
        if not self.available:
            return {}
        try:
            r = httpx.get(
                _API_URL,
                params={"ipAddress": ip, "maxAgeInDays": _MAX_AGE_DAYS},
                headers={"Key": self._api_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            r.raise_for_status()
            data = r.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0) / 100.0
            isp = data.get("isp", "")
            domain = data.get("domain", "")
            asn_org = f"{isp} ({domain})" if domain and domain not in isp else isp
            return {
                "threat_score": score,
                "is_known_malicious": score >= 0.5,
                "country_code": data.get("countryCode", ""),
                "asn_org": asn_org.strip(),
                "total_reports": data.get("totalReports", 0),
                "sources_hit": [self.name],
            }
        except Exception as exc:
            logger.debug("AbuseIPDB lookup(%s) falló: %s", ip, exc)
            return {}

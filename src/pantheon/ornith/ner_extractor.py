"""Extracción de IOCs (indicadores de compromiso) de texto vía patrones regex.

No se usa un modelo de NER de lenguaje natural porque los IOCs de seguridad
(IPs, hashes, CVE-IDs, dominios) son patrones estructurados, no entidades
lingüísticas — regex es más barato, más preciso y no requiere inferencia.
"""

import re

_PATTERNS: dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|online)\b",
        re.IGNORECASE,
    ),
}


def extract_iocs(text: str) -> list[str]:
    """Extrae todos los IOCs reconocidos de un texto, sin duplicados.

    Nota: el orden de evaluación importa. SHA256 (64 hex) y SHA1 (40 hex)
    se evalúan antes que MD5 (32 hex) para evitar que un hash largo se
    capture parcialmente como uno corto si los patrones se traslaparan
    (en este caso no se traslapan por longitud exacta, pero se deja el
    orden explícito por claridad y para futuras extensiones).
    """
    found: set[str] = set()
    for label in ("cve", "sha256", "sha1", "md5", "ipv4", "domain"):
        pattern = _PATTERNS[label]
        for match in pattern.findall(text):
            found.add(match)
    return sorted(found)
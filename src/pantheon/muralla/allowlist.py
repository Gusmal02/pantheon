"""
Allowlist de playbooks curados para Muralla.

Carga el archivo policy/curated_playbooks.json y expone una función
de lookup por hash SHA-256. Solo los playbooks en esta lista pueden
ser ejecutados — el LLM nunca decide, solo el hash.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DEFAULT_POLICY_PATH = Path("policy/curated_playbooks.json")


@dataclass
class PlaybookMeta:
    id: str
    name: str
    action: str
    parameters_schema: dict
    emergency: bool
    requires_approval: bool
    hash_sha256: str


class PlaybookAllowlist:
    """
    Allowlist inmutable de playbooks curados.

    Uso:
        allowlist = PlaybookAllowlist.from_json("policy/curated_playbooks.json")
        meta = allowlist.lookup_by_hash(sha256_of_playbook_json)
        if meta is None:
            raise PlaybookNotAllowed("hash no registrado")
    """

    def __init__(self, playbooks: list[PlaybookMeta]) -> None:
        self._by_hash: dict[str, PlaybookMeta] = {pb.hash_sha256: pb for pb in playbooks}
        self._by_id:   dict[str, PlaybookMeta] = {pb.id: pb for pb in playbooks}

    @classmethod
    def from_json(cls, path: Path | str = _DEFAULT_POLICY_PATH) -> "PlaybookAllowlist":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        playbooks = [
            PlaybookMeta(
                id=pb["id"],
                name=pb["name"],
                action=pb["action"],
                parameters_schema=pb.get("parameters_schema", {}),
                emergency=pb.get("emergency", False),
                requires_approval=pb.get("requires_approval", True),
                hash_sha256=pb["hash_sha256"],
            )
            for pb in data.get("playbooks", [])
        ]
        return cls(playbooks)

    def lookup_by_hash(self, sha256: str) -> Optional[PlaybookMeta]:
        """Devuelve los metadatos del playbook si el hash está registrado."""
        return self._by_hash.get(sha256)

    def lookup_by_id(self, playbook_id: str) -> Optional[PlaybookMeta]:
        return self._by_id.get(playbook_id)

    @property
    def registered_hashes(self) -> set[str]:
        return set(self._by_hash.keys())

    @staticmethod
    def compute_hash(playbook_json: dict | str) -> str:
        """
        Calcula el SHA-256 de un playbook para comparar contra la allowlist.
        El hash se calcula sobre la representación JSON canónica (sort_keys=True).
        """
        if isinstance(playbook_json, dict):
            canonical = json.dumps(playbook_json, sort_keys=True)
        else:
            canonical = playbook_json
        return hashlib.sha256(canonical.encode()).hexdigest()

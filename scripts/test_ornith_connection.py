"""Script de prueba: confirma que Ornith puede crear colección, indexar y buscar."""

import uuid
from datetime import datetime

from pantheon.ornith.client import ensure_collection, index_episode, search_hybrid
from pantheon.ornith.episode_schema import Episode, TTPTag

ensure_collection()
print("Colección lista.")

episode = Episode(
    id=str(uuid.uuid4()),
    timestamp=datetime.now(),
    anomaly_signature="Tráfico DNS anómalo hacia múltiples dominios externos en ventana de 5 min",
    hypothesis="Posible beaconing de C2 vía DNS tunneling",
    ttp_tags=[TTPTag.COMMAND_AND_CONTROL],
    iocs_extraidos=["evil-domain.example.com"],
)
index_episode(episode)
print(f"Episodio indexado: {episode.id}")

results = search_hybrid("tráfico DNS sospechoso hacia dominios externos")
print(f"Episodios encontrados: {len(results)}")
for r in results:
    print(f"  - {r.hypothesis}")
    
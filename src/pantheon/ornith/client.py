"""Cliente de Qdrant para Ornith: creación de colección, indexación y búsqueda híbrida."""

import uuid

from qdrant_client import QdrantClient, models

from pantheon.core.config import settings
from pantheon.ornith.embedding import embed_dense, embed_sparse
from pantheon.ornith.episode_schema import Episode

DENSE_VECTOR_NAME = "dense"
SPARSE_VECTOR_NAME = "sparse"
DENSE_VECTOR_SIZE = 384  # tamaño de salida de BAAI/bge-small-en-v1.5

client = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)


def ensure_collection() -> None:
    """Crea la colección de episodios si no existe, con soporte hybrid dense+sparse."""
    collection_name = settings.qdrant_collection_episodes
    if client.collection_exists(collection_name):
        return

    client.create_collection(
        collection_name=collection_name,
        vectors_config={
            DENSE_VECTOR_NAME: models.VectorParams(
                size=DENSE_VECTOR_SIZE, distance=models.Distance.COSINE
            )
        },
        sparse_vectors_config={SPARSE_VECTOR_NAME: models.SparseVectorParams()},
    )


def index_episode(episode: Episode) -> None:
    """Indexa un episodio: vectoriza anomaly_signature + hypothesis, guarda el resto como payload."""
    text_to_embed = f"{episode.anomaly_signature}. {episode.hypothesis}"
    dense_vector = embed_dense(text_to_embed)
    sparse_vector = embed_sparse(text_to_embed)

    client.upsert(
        collection_name=settings.qdrant_collection_episodes,
        points=[
            models.PointStruct(
                id=episode.id,
                vector={
                    DENSE_VECTOR_NAME: dense_vector,
                    SPARSE_VECTOR_NAME: models.SparseVector(**sparse_vector),
                },
                payload=episode.model_dump(mode="json"),
            )
        ],
    )


def search_hybrid(query: str, limit: int = 5) -> list[Episode]:
    """Búsqueda híbrida dense+sparse con RRF, devuelve los episodios más similares."""
    dense_vector = embed_dense(query)
    sparse_vector = embed_sparse(query)

    results = client.query_points(
        collection_name=settings.qdrant_collection_episodes,
        prefetch=[
            models.Prefetch(
                query=dense_vector, using=DENSE_VECTOR_NAME, limit=limit * 2
            ),
            models.Prefetch(
                query=models.SparseVector(**sparse_vector),
                using=SPARSE_VECTOR_NAME,
                limit=limit * 2,
            ),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=limit,
    )

    return [Episode(**point.payload) for point in results.points]
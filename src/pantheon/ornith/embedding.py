"""Generación de embeddings dense y sparse para episodios de Ornith."""

from fastembed import SparseTextEmbedding, TextEmbedding

# Modelo dense: liviano, buena calidad para texto en inglés/técnico (logs, CVEs, ATT&CK).
_DENSE_MODEL_NAME = "BAAI/bge-small-en-v1.5"
# Modelo sparse: equivalente a BM25, captura coincidencias léxicas exactas
# (IDs de CVE, nombres de técnica, hashes) que el embedding denso puede pasar por alto.
_SPARSE_MODEL_NAME = "Qdrant/bm25"

_dense_model = TextEmbedding(model_name=_DENSE_MODEL_NAME)
_sparse_model = SparseTextEmbedding(model_name=_SPARSE_MODEL_NAME)


def embed_dense(text: str) -> list[float]:
    """Genera el vector denso de un texto."""
    return list(_dense_model.embed([text]))[0].tolist()


def embed_sparse(text: str) -> dict[str, list]:
    """Genera el vector sparse (BM25) de un texto, en formato compatible con Qdrant."""
    result = list(_sparse_model.embed([text]))[0]
    return {
        "indices": result.indices.tolist(),
        "values": result.values.tolist(),
    }
"""Tests unitarios para el Semantic Cache."""

import numpy as np
import pytest

from pantheon.cache.semantic import SemanticCache


class TestSemanticCache:
    def _cache(self) -> SemanticCache:
        return SemanticCache(redis_client=None, ttl_secs=60)

    def _vec(self, seed: int = 0) -> np.ndarray:
        return np.random.default_rng(seed).uniform(0, 1, 8)

    def test_miss_on_empty_cache(self):
        cache = self._cache()
        result = cache.get(self._vec(), ["doc1"], "tmpl_abc")
        assert result is None

    def test_put_and_get_hit(self):
        cache = self._cache()
        vec = self._vec()
        doc_ids = ["doc1", "doc2"]
        template = "tmpl_001"
        hypotheses = [{"id": "h1", "text": "lateral movement"}]
        cache.put(vec, doc_ids, template, hypotheses)
        result = cache.get(vec, doc_ids, template)
        assert result == hypotheses

    def test_different_vector_is_miss(self):
        cache = self._cache()
        doc_ids = ["doc1"]
        template = "tmpl_001"
        cache.put(self._vec(seed=0), doc_ids, template, [{"id": "h1"}])
        # vector diferente → miss
        result = cache.get(self._vec(seed=1), doc_ids, template)
        assert result is None

    def test_different_doc_ids_is_miss(self):
        cache = self._cache()
        vec = self._vec()
        template = "tmpl_001"
        cache.put(vec, ["doc1"], template, [{"id": "h1"}])
        result = cache.get(vec, ["doc2"], template)
        assert result is None

    def test_different_template_is_miss(self):
        cache = self._cache()
        vec = self._vec()
        doc_ids = ["doc1"]
        cache.put(vec, doc_ids, "tmpl_001", [{"id": "h1"}])
        result = cache.get(vec, doc_ids, "tmpl_002")
        assert result is None

    def test_doc_id_order_invariant(self):
        cache = self._cache()
        vec = self._vec()
        template = "tmpl_001"
        hypotheses = [{"id": "h1"}]
        cache.put(vec, ["doc1", "doc2"], template, hypotheses)
        result = cache.get(vec, ["doc2", "doc1"], template)
        assert result == hypotheses

    def test_invalidate_removes_entry(self):
        cache = self._cache()
        vec = self._vec()
        doc_ids = ["doc1"]
        template = "tmpl_001"
        fp = cache.put(vec, doc_ids, template, [{"id": "h1"}])
        cache.invalidate(fp)
        assert cache.get(vec, doc_ids, template) is None

    def test_stats_tracks_hits_and_misses(self):
        cache = self._cache()
        vec = self._vec()
        cache.put(vec, ["doc1"], "t", [{"id": "h1"}])
        cache.get(vec, ["doc1"], "t")   # hit
        cache.get(vec, ["doc2"], "t")   # miss
        stats = cache.stats()
        assert stats.hits == 1
        assert stats.misses == 1
        assert stats.hit_rate == pytest.approx(0.5)

    def test_stats_zero_on_empty(self):
        stats = self._cache().stats()
        assert stats.hit_rate == 0.0
        assert stats.hits == 0

    def test_fingerprint_deterministic(self):
        vec = self._vec()
        fp1 = SemanticCache._fingerprint(vec, ["d1"], "t")
        fp2 = SemanticCache._fingerprint(vec, ["d1"], "t")
        assert fp1 == fp2

    def test_fingerprint_is_hex_64_chars(self):
        fp = SemanticCache._fingerprint(self._vec(), ["d1"], "t")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

"""Tests unitarios para la configuración central de Pantheon."""

import pytest

from pantheon.core.config import Settings


class TestSettings:
    def test_defaults_load(self):
        s = Settings(_env_file=None)
        assert s.qdrant_host == "localhost"
        assert s.qdrant_port == 6333
        assert s.postgres_port == 5432
        assert s.worm_enabled is False

    def test_postgres_dsn_format(self):
        s = Settings(_env_file=None, postgres_password="secret", postgres_host="db")
        dsn = s.postgres_dsn
        assert dsn.startswith("postgresql://")
        assert "secret" in dsn
        assert "db" in dsn

    def test_postgres_dsn_async_format(self):
        s = Settings(_env_file=None)
        assert s.postgres_dsn_async.startswith("postgresql+asyncpg://")

    def test_cci_thresholds_valid_range(self):
        s = Settings(_env_file=None)
        assert 0.0 < s.cci_ambiguous_threshold < s.cci_critical_threshold < 1.0

    def test_enclave_key_generated_if_not_set(self):
        s1 = Settings(_env_file=None)
        s2 = Settings(_env_file=None)
        # cada instancia genera una clave distinta cuando no se fija en env
        # (ambas deben ser hexadecimales de 64 chars)
        assert len(s1.pantheon_enclave_key) == 64
        assert len(s2.pantheon_enclave_key) == 64

    def test_enclave_log_path_is_path_object(self):
        from pathlib import Path
        s = Settings(_env_file=None)
        assert isinstance(s.pantheon_enclave_log, Path)

    def test_redis_url_default(self):
        s = Settings(_env_file=None)
        assert s.redis_url.startswith("redis://")

    def test_approval_timeout_positive(self):
        s = Settings(_env_file=None)
        assert s.pantheon_approval_timeout_secs > 0

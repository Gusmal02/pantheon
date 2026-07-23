"""Configuración central de Pantheon, cargada desde variables de entorno."""

import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variables de entorno del proyecto. Ver .env.example para referencia."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection_episodes: str = "pantheon_episodes"

    # PostgreSQL
    postgres_user: str = "pantheon"
    postgres_password: str = ""
    postgres_db: str = "pantheon"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Auth / JWT
    pantheon_jwt_secret: str = secrets.token_hex(32)
    pantheon_jwt_expire_hours: int = 1
    pantheon_enclave_key: str = secrets.token_hex(32)

    # Audit / Outbox
    pantheon_enclave_log: Path = Path("audit/precommit.log")
    pantheon_outbox_poll_secs: int = 5

    # WORM
    worm_endpoint: str = "http://localhost:9000/pantheon-audit"
    worm_timeout_secs: int = 5
    worm_enabled: bool = False

    # CCI thresholds
    cci_ambiguous_threshold: float = 0.45
    cci_critical_threshold: float = 0.75

    # Input Guard
    input_guard_rate_limit: int = 50
    input_guard_cb_cooldown_secs: int = 30

    # Approval Gate
    pantheon_approval_timeout_secs: int = 600

    # Purple Team
    ares_api_url: str = "http://localhost:8000"
    ares_poll_cb_failures: int = 5   # fallos HTTP antes de abrir el circuit breaker

    # Ollama (LLM local)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"

    # Rate limiting de la API REST
    api_rate_limit: int = 120   # max requests por IP por minuto

    # OSINT — enrichment de threat intelligence externa para Hermes
    abuseipdb_api_key: str = ""          # API key de AbuseIPDB (gratis en abuseipdb.com)
    osint_cache_ttl_secs: int = 3600     # TTL del caché en memoria (1 hora)
    osint_request_timeout_secs: int = 5  # timeout por fuente OSINT

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_dsn_async(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()

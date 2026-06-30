"""Configuración central de Pantheon, cargada desde variables de entorno."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Variables de entorno del proyecto. Ver .env.example para referencia."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_collection_episodes: str = "pantheon_episodes"

    # PostgreSQL (usado más adelante por Acme)
    postgres_user: str = "pantheon"
    postgres_password: str = ""
    postgres_db: str = "pantheon"
    postgres_host: str = "localhost"
    postgres_port: int = 5432


settings = Settings()
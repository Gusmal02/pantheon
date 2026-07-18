"""Inicializa el schema de PostgreSQL para Pantheon v2.1.

Lee el DDL desde scripts/schema.sql (fuente única de verdad compartida con start-dev.ps1).

Uso directo (requiere acceso TCP a Postgres):
    uv run python scripts/init_db.py

En start-dev.ps1 el schema se aplica via docker exec psql (sin TCP al host).
"""

import os
import sys
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

load_dotenv()

SCHEMA_FILE = Path(__file__).parent / "schema.sql"


def main() -> None:
    ddl = SCHEMA_FILE.read_text(encoding="utf-8")

    conn_params = {
        "host":     os.environ.get("POSTGRES_HOST",     "localhost"),
        "port":     int(os.environ.get("POSTGRES_PORT", "5432")),
        "dbname":   os.environ.get("POSTGRES_DB",       "pantheon"),
        "user":     os.environ.get("POSTGRES_USER",     "pantheon"),
        "password": os.environ.get("POSTGRES_PASSWORD", ""),
    }

    try:
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.close()
        print("Schema inicializado correctamente.")
    except psycopg2.OperationalError as exc:
        print(f"Error conectando a PostgreSQL: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

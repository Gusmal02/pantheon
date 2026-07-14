"""Inicializa el schema de PostgreSQL para Pantheon v2.1.

Tablas:
  audit_trail — registro inmutable con hash encadenado y patrón Outbox
                (replicated=FALSE hasta que el worker genere pre-commit log + WORM)
  episodes    — episodios de threat hunting (metadatos; payload completo en Qdrant)
  operators   — perfiles de analista para Acme Ranker (IPCA)
"""

import os
import sys

import psycopg2
from dotenv import load_dotenv

load_dotenv()

DDL = """
-- Audit Trail con patrón Transactional Outbox
-- El worker independiente marca replicated=TRUE tras generar pre-commit log + WORM.
CREATE TABLE IF NOT EXISTS audit_trail (
    id              UUID        PRIMARY KEY,
    event_type      TEXT        NOT NULL,
    operator_id     TEXT        NOT NULL,
    details         JSONB       NOT NULL DEFAULT '{}',
    chain_hash      TEXT        NOT NULL,
    pre_commit_hash TEXT        NOT NULL DEFAULT '',
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    jit_pin         TEXT        NOT NULL DEFAULT '',
    approved        BOOLEAN     NOT NULL DEFAULT FALSE,
    replicated      BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_audit_trail_replicated
    ON audit_trail (replicated, timestamp)
    WHERE replicated = FALSE;

CREATE INDEX IF NOT EXISTS idx_audit_trail_operator
    ON audit_trail (operator_id, timestamp DESC);

-- Episodios de hunting (metadatos; payload completo vive en Qdrant)
CREATE TABLE IF NOT EXISTS episodes (
    id              UUID        PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    operator_id     TEXT        NOT NULL,
    ttp_tags        TEXT[]      NOT NULL DEFAULT '{}',
    campaign_id     UUID,
    outcome         TEXT        NOT NULL DEFAULT 'open',
    qdrant_id       TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_episodes_operator ON episodes (operator_id);
CREATE INDEX IF NOT EXISTS idx_episodes_campaign ON episodes (campaign_id);

-- Perfiles de analista para Acme Ranker
CREATE TABLE IF NOT EXISTS operators (
    operator_id     TEXT        PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    feedback_count  INTEGER     NOT NULL DEFAULT 0,
    ipca_state      BYTEA,
    calibrated      BOOLEAN     NOT NULL DEFAULT FALSE
);

-- Escalados del Purple Team Bridge (Ares v3.2 → Pantheon)
CREATE TABLE IF NOT EXISTS purple_escalated (
    content_hash    TEXT            PRIMARY KEY,
    hypothesis_id   TEXT            NOT NULL,
    source_ip       TEXT            NOT NULL,
    ttp_tags        TEXT[]          NOT NULL DEFAULT '{}',
    severity        TEXT            NOT NULL DEFAULT 'moderate',
    narrative       TEXT            NOT NULL,
    ares_source     TEXT            NOT NULL,
    timestamp_ts    DOUBLE PRECISION NOT NULL,
    received_at     DOUBLE PRECISION NOT NULL,
    processed       BOOLEAN         NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_purple_escalated_unprocessed
    ON purple_escalated (processed, received_at DESC)
    WHERE processed = FALSE;

CREATE INDEX IF NOT EXISTS idx_purple_escalated_received
    ON purple_escalated (received_at DESC);
"""


def main() -> None:
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
            cur.execute(DDL)
        conn.close()
        print("Schema inicializado correctamente.")
    except psycopg2.OperationalError as exc:
        print(f"Error conectando a PostgreSQL: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

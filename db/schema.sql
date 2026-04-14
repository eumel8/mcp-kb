-- MCP-KB Incident Knowledge Base – PostgreSQL + pgvector schema
-- Apply once against the target database:
--   psql -U <user> -d <db> -f schema.sql

-- Enable the pgvector extension (requires PostgreSQL ≥ 14 + pgvector ≥ 0.5)
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------------------
-- One row per resolved incident.  The embedding is generated from a
-- concatenation of title + description + resolution and stored as a
-- 1536-dimensional vector (OpenAI text-embedding-3-small / ada-002 compatible).
-- Adjust the dimension constant if you use a different embedding model.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Human-readable identifiers
    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,           -- symptom / what went wrong
    affected_component  TEXT        NOT NULL,           -- e.g. "cluster/ship-lab-1", "ingress-nginx"
    severity            TEXT        NOT NULL            -- Critical | Major | Minor | Uncritical
                            CHECK (severity IN ('Critical','Major','Minor','Uncritical')),
    environment         TEXT        NOT NULL DEFAULT 'prod',  -- prod | preprod | av | playground

    -- Resolution
    root_cause          TEXT,                           -- identified root cause
    resolution          TEXT        NOT NULL,           -- what fixed it
    runbook_url         TEXT,                           -- optional link to runbook / wiki

    -- Tags for structured filtering (e.g. "oom", "crashloopbackoff", "network")
    tags                TEXT[]      NOT NULL DEFAULT '{}',

    -- External references
    casm_ticket_id      TEXT,                           -- linked CASM ticket
    alert_name          TEXT,                           -- Prometheus/Alertmanager alert name

    -- Provenance
    reported_by         TEXT,
    resolved_by         TEXT,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- embeddings
-- ---------------------------------------------------------------------------
-- Separated from the incidents table so the dimension can be changed without
-- an ALTER TABLE on the main data table and to allow multiple embedding
-- strategies side-by-side.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_embeddings (
    incident_id         UUID        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    model               TEXT        NOT NULL DEFAULT 'text-embedding-3-small',
    -- 1536 dimensions for OpenAI text-embedding-3-small / text-embedding-ada-002
    embedding           vector(1536) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, model)
);

-- IVFFlat index for approximate nearest-neighbour search.
-- lists = sqrt(number of rows) is a common starting point; tune for your data.
-- Cosine similarity is used because embeddings are typically normalised.
CREATE INDEX IF NOT EXISTS incident_embeddings_ivfflat_idx
    ON incident_embeddings
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ---------------------------------------------------------------------------
-- Trigger: keep updated_at current on incidents
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS incidents_updated_at ON incidents;
CREATE TRIGGER incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Convenience view: incidents with their latest embedding metadata
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW incidents_with_embeddings AS
SELECT
    i.*,
    e.model       AS embedding_model,
    e.created_at  AS embedded_at,
    (e.embedding IS NOT NULL) AS has_embedding
FROM incidents i
LEFT JOIN incident_embeddings e ON e.incident_id = i.id AND e.model = 'text-embedding-3-small';

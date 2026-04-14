-- MCP-KB Incident Knowledge Base – PostgreSQL schema
-- Apply once against the target database:
--   psql -U <user> -d <db> -f schema.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------------------------------
-- incidents
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),

    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,
    affected_component  TEXT        NOT NULL,
    severity            TEXT        NOT NULL
                            CHECK (severity IN ('Critical','Major','Minor','Uncritical')),
    environment         TEXT        NOT NULL DEFAULT 'prod',

    root_cause          TEXT,
    resolution          TEXT        NOT NULL,
    runbook_url         TEXT,

    tags                TEXT[]      NOT NULL DEFAULT '{}',

    casm_ticket_id      TEXT        UNIQUE,
    alert_name          TEXT,

    reported_by         TEXT,
    resolved_by         TEXT,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Full-text search vector: weighted combination of all text fields.
    -- 'A' = title (highest weight), 'B' = affected_component + severity,
    -- 'C' = root_cause + resolution, 'D' = description + tags (lowest weight).
    search_vector       TSVECTOR
);

-- GIN index for fast full-text search.
CREATE INDEX IF NOT EXISTS incidents_search_vector_idx
    ON incidents USING GIN (search_vector);

-- ---------------------------------------------------------------------------
-- Trigger: maintain search_vector and updated_at automatically
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION incidents_update_trigger()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at     := NOW();
    NEW.search_vector  :=
        setweight(to_tsvector('english', COALESCE(NEW.title, '')),        'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.affected_component, '') || ' ' || COALESCE(NEW.severity, '')), 'B') ||
        setweight(to_tsvector('english', COALESCE(NEW.root_cause, '') || ' ' || COALESCE(NEW.resolution, '')),       'C') ||
        setweight(to_tsvector('english', COALESCE(NEW.description, '') || ' ' || array_to_string(COALESCE(NEW.tags, '{}'), ' ')), 'D');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS incidents_update_trigger ON incidents;
CREATE TRIGGER incidents_update_trigger
    BEFORE INSERT OR UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incidents_update_trigger();

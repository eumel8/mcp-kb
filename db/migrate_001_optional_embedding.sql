-- Migration 001: make incident_embeddings optional
-- Run once against the existing database if incident_embeddings already exists.
-- This is a no-op if the table does not yet exist (schema.sql handles creation).

-- The incident_embeddings table already has no NOT NULL on embedding column
-- at the table level (NOT NULL is implied by the column definition in the
-- original schema.sql).  The only change needed is to allow incidents to exist
-- without a corresponding row in incident_embeddings, which is already the
-- case because it is a separate table with a FK (no NOT NULL on incidents side).
-- This migration is therefore informational only – no DDL change is required.

-- Ensure the ivfflat index only covers rows with embeddings (already implicit).
-- Nothing to change – the schema already supports optional embeddings.

SELECT 'migration 001: no DDL changes required – optional embeddings supported' AS status;

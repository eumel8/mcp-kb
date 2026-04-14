-- Migration 002: Replace pgvector embeddings with PostgreSQL full-text search
--
-- Removes the incident_embeddings table (and the dependent view),
-- drops the old updated_at-only trigger, adds the search_vector tsvector
-- column, creates a combined INSERT/UPDATE trigger that maintains both
-- updated_at and search_vector, back-fills existing rows, and creates a
-- GIN index for fast full-text queries.
--
-- Safe to run on a live database; everything is wrapped in a transaction.

BEGIN;

-- 1. Drop the embedding-based view and table (pgvector no longer used)
DROP VIEW  IF EXISTS incidents_with_embeddings;
DROP TABLE IF EXISTS incident_embeddings CASCADE;

-- 2. Drop the old updated_at-only trigger and its function
DROP TRIGGER IF EXISTS incidents_updated_at ON incidents;
DROP FUNCTION IF EXISTS set_updated_at() CASCADE;

-- 3. Add the full-text search column (idempotent)
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS search_vector tsvector;

-- 4. Create the combined trigger function
CREATE OR REPLACE FUNCTION incidents_update_trigger_fn()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  NEW.search_vector :=
    setweight(to_tsvector('english', coalesce(NEW.title,              '')), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.description,        '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.root_cause,         '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.resolution,         '')), 'C') ||
    setweight(to_tsvector('english', coalesce(NEW.affected_component, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(array_to_string(NEW.tags, ' '), '')), 'B');
  RETURN NEW;
END;
$$;

-- 5. Attach the trigger for both INSERT and UPDATE
DROP TRIGGER IF EXISTS incidents_update_trigger ON incidents;
CREATE TRIGGER incidents_update_trigger
  BEFORE INSERT OR UPDATE ON incidents
  FOR EACH ROW EXECUTE FUNCTION incidents_update_trigger_fn();

-- 6. Back-fill search_vector for any existing rows
UPDATE incidents SET updated_at = updated_at;

-- 7. GIN index for fast full-text queries
CREATE INDEX IF NOT EXISTS incidents_search_vector_idx
  ON incidents USING GIN (search_vector);

COMMIT;

-- Migration 003: Add git_commit column to incidents
--
-- Stores the Git commit SHA that caused the incident (nullable).
-- Useful for correlating config changes (GitOps commits) with incidents.
--
-- Safe to run on a live database.

BEGIN;

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS git_commit TEXT;

COMMIT;

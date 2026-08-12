-- Existing installations need a nullable column because old, immutable
-- verdicts predate scanner_version. New submissions require it in the API;
-- COALESCE in store reads exposes an empty value only for those legacy rows.
BEGIN;

ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS scanner_version TEXT;

COMMIT;

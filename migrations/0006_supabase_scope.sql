-- Supabase project coverage is attested evidence, not an API-only display
-- field. Keep it alongside immutable verdicts so historical browser hash
-- verification can reconstruct the exact attested content.
BEGIN;

ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS supabase_organization_id TEXT,
    ADD COLUMN IF NOT EXISTS projects_listed TEXT[],
    ADD COLUMN IF NOT EXISTS projects_scanned TEXT[];

COMMIT;

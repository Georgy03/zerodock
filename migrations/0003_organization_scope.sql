-- Organization coverage became part of the attested wire format in week 8.
-- Columns remain nullable for immutable legacy verdicts; the API requires and
-- validates these fields on every new submission.
BEGIN;

ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS organization_verified BOOLEAN,
    ADD COLUMN IF NOT EXISTS org_id TEXT,
    ADD COLUMN IF NOT EXISTS no_organization BOOLEAN,
    ADD COLUMN IF NOT EXISTS organization_warning TEXT,
    ADD COLUMN IF NOT EXISTS accounts_listed TEXT[],
    ADD COLUMN IF NOT EXISTS accounts_scanned TEXT[];

COMMIT;

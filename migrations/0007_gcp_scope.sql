-- GCP project coverage is independently attested and must be retained with
-- immutable verdicts; it cannot be reconstructed from a mutable API index.
BEGIN;
ALTER TABLE verdicts
    ADD COLUMN IF NOT EXISTS gcp_organization_id TEXT,
    ADD COLUMN IF NOT EXISTS gcp_projects_listed TEXT[],
    ADD COLUMN IF NOT EXISTS gcp_projects_scanned TEXT[];
COMMIT;

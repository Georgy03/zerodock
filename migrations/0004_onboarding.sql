-- Week-12 onboarding flow. Deliberately a separate table from share_links:
-- share_links.account_id is NOT NULL UNIQUE and represents a scanned
-- account with real verdicts attached, whereas an onboarding row exists
-- BEFORE any scan happens — often before ZeroDock has ever successfully
-- called AWS on the vendor's behalf at all. Mixing the two would mean
-- either relaxing share_links' NOT NULL constraint (weakening a guarantee
-- unrelated rows depend on) or writing placeholder verdict rows, neither
-- of which is worth it for what is fundamentally a different entity: a
-- request to connect, not a connection.
BEGIN;

CREATE TABLE IF NOT EXISTS onboardings (
    tenant_id            TEXT PRIMARY KEY,
    customer_account_id  TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS onboardings_customer_account_id_idx
    ON onboardings (customer_account_id);

-- Status is derived live from AWS on every poll, never stored — so
-- zerodock_app only ever needs to create and read a row, never update one.
GRANT SELECT, INSERT ON onboardings TO zerodock_app;

COMMIT;

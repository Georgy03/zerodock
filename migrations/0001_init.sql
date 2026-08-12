-- Week-5 backend schema.
--
-- Run this as a privileged role (the database owner, or whatever role your
-- migration tooling connects as) — NOT the role the API server itself
-- connects as. The whole point of the REVOKE statements at the bottom is
-- that the role the running server uses (zerodock_app) is NOT allowed to
-- run them again, or to undo them: append-only has to be enforced by
-- POSTGRES ITSELF, not by "our application code just happens to never
-- call UPDATE or DELETE". A bug, or a fully compromised API server
-- process, still cannot alter or erase a verdict once it's written.

BEGIN;

-- share_links maps a buyer-facing token to the AWS account it covers —
-- this is the REAL, explicit entity a "GET /v1/share/{token}" URL
-- resolves against, not a value derived on the fly from account_id. One
-- row per link; vendor_id and label exist for the (not yet built)
-- provisioning flow where a vendor explicitly creates and names a link
-- for a customer, rather than one being silently minted the first time
-- an account happens to show up in a scan. Until that flow exists,
-- internal/store.CreateVerdict auto-creates a link (vendor_id/label left
-- NULL) the first time it sees a new account_id, purely so
-- POST /v1/verdicts has somewhere to attach a token today — that's a
-- placeholder behavior, not the intended long-term provisioning story.
--
-- revoked_at lets a link be killed without deleting any history: once
-- set, internal/api's GET handlers refuse to resolve it (410), but the
-- verdicts rows underneath are untouched — revoking a LINK is not the
-- same operation as erasing EVIDENCE, and only the latter is supposed to
-- be structurally impossible in this schema.
CREATE TABLE IF NOT EXISTS share_links (
    token       TEXT PRIMARY KEY,
    vendor_id   TEXT,
    account_id  TEXT NOT NULL UNIQUE,
    label       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

-- verdicts is the append-only ledger: one row per successfully verified
-- scan report. Nothing about a row is ever supposed to change after it's
-- inserted — that's both a data-integrity property (a verdict a buyer
-- already saw should never silently change under them) and a legal-ish
-- one (it's the evidence trail).
CREATE TABLE IF NOT EXISTS verdicts (
    id                  BIGSERIAL PRIMARY KEY,
    share_token         TEXT NOT NULL REFERENCES share_links(token),
    scanner_version     TEXT NOT NULL,
    organization_verified BOOLEAN NOT NULL,
    org_id              TEXT,
    no_organization     BOOLEAN NOT NULL,
    organization_warning TEXT,
    accounts_listed     TEXT[] NOT NULL,
    accounts_scanned    TEXT[] NOT NULL,

    -- scan_id is the enclave-generated ID from the report itself (see
    -- newScanID in cmd/scanner/main.go) — UNIQUE here means submitting
    -- the exact same report twice is rejected as a duplicate rather than
    -- silently creating two rows for one scan.
    scan_id             TEXT NOT NULL UNIQUE,
    account_id          TEXT NOT NULL,

    -- attested_at is the report's OWN `timestamp` field — the
    -- hardware-attested time the scan actually ran (see "Time: an
    -- enclave has no reliable clock either" in the top-level README).
    -- received_at is simply when THIS SERVER saw the submission, which
    -- can legitimately be later (network delay, retries) — keeping both
    -- means "latest" queries can be answered by attested_at (what
    -- actually happened first) rather than accidentally by arrival order.
    --
    -- NEITHER of these is a freshness check. A verdict attested two years
    -- ago is still stored and still verifies (see the big comment on
    -- verifyChain in internal/verify) — attested_at lets a CONSUMER of
    -- this table decide "is this too old", it doesn't decide that here.
    attested_at         TIMESTAMPTZ NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    scope_verified      BOOLEAN NOT NULL,
    scope_warning       TEXT,
    time_verified       BOOLEAN NOT NULL,
    time_warning        TEXT,

    requested_regions   TEXT[] NOT NULL,
    scanned_regions     TEXT[] NOT NULL,
    regions_warning     TEXT,

    results_sha384      TEXT NOT NULL,
    checks              JSONB NOT NULL,

    attestation_format  TEXT NOT NULL,

    -- attestation_mock is TRUE when this verdict's attestation chained to
    -- a MockAttester root rather than the real AWS Nitro root (see
    -- internal/verify.Outcome.Mock) — recorded so a mock verdict can
    -- never be mistaken for a hardware-backed one after the fact, even
    -- if a future bug in the API layer started allowing mock submissions
    -- into the same table as real ones.
    attestation_mock    BOOLEAN NOT NULL,

    -- pcrs is {"0": "hex...", "1": "hex...", "2": "hex..."} — kept
    -- alongside the raw bytes below so a PCR0 can be queried/displayed
    -- without re-parsing the whole COSE document on every read.
    pcrs                JSONB NOT NULL,

    -- attestation_raw is the exact bytes the enclave produced and this
    -- server verified — stored VERBATIM, never re-encoded or
    -- re-derived, forever. This is the actual evidence; everything else
    -- in this row is convenience/queryability derived from it.
    attestation_raw     BYTEA NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The query GET /v1/share/{token} and .../history both run: "every
-- verdict for this token, newest attested first".
CREATE INDEX IF NOT EXISTS verdicts_share_token_attested_at_idx
    ON verdicts (share_token, attested_at DESC);

-- zerodock_app is the role the API server itself connects as — distinct
-- from whatever role ran this migration. Its password should come from a
-- secrets manager in any real deployment, not be hardcoded the way it is
-- here; this migration only needs the role to EXIST so the GRANT/REVOKE
-- statements below have something to target.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'zerodock_app') THEN
        CREATE ROLE zerodock_app LOGIN PASSWORD 'changeme-set-via-secrets-manager';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO zerodock_app;

-- share_links: the app needs to create new links (today's placeholder
-- auto-creation — see the comment on the table above) and read existing
-- ones. UPDATE is needed both for that auto-creation's harmless no-op
-- upsert and for a future revoke operation (setting revoked_at) — this
-- table is a small, mutable lookup/administration table, not the
-- evidence ledger, so it doesn't need to be append-only the way verdicts
-- does.
GRANT SELECT, INSERT, UPDATE ON share_links TO zerodock_app;

-- verdicts: append-only, enforced HERE, not just in application code.
GRANT SELECT, INSERT ON verdicts TO zerodock_app;
REVOKE UPDATE, DELETE ON verdicts FROM zerodock_app;

-- BIGSERIAL columns need explicit sequence access to INSERT at all.
GRANT USAGE, SELECT ON SEQUENCE verdicts_id_seq TO zerodock_app;

COMMIT;

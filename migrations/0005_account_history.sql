-- Scope drift tracking. One row per (verdict, account) pair: every
-- account a scan's attested content lists, whether or not the scanner
-- actually reached it, so drift can be reconstructed later without
-- re-deriving it from scratch each time.
--
-- This table is bookkeeping, not the trust boundary. The buyer-facing
-- scope_events comparison is computed CLIENT-SIDE from two independently
-- verified attested verdicts (see web/src/verify/scope.ts) — this table
-- exists so the SERVER can cheaply answer "when was this account first
-- seen" and "what did the last N scans' coverage look like" without
-- walking every historical attestation on every request, not so a buyer
-- has to trust a server-asserted diff. internal/scope.Detect is the same
-- pure logic used to classify rows here, mirrored (not re-implemented
-- differently) on the browser side.
BEGIN;

CREATE TABLE IF NOT EXISTS account_history (
    id             BIGSERIAL PRIMARY KEY,
    share_token    TEXT NOT NULL REFERENCES share_links(token),
    verdict_id     BIGINT NOT NULL REFERENCES verdicts(id),
    org_id         TEXT,
    account_id     TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('scanned', 'listed_unreachable')),
    -- The earliest attested_at at which this account_id was ever listed
    -- under this share_token — carried forward from prior rows, not
    -- reset if an account temporarily disappears and later reappears.
    first_seen_at  TIMESTAMPTZ NOT NULL,
    -- This row's own verdict's attested_at — i.e. when THIS observation
    -- was made, distinct from first_seen_at.
    observed_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (verdict_id, account_id)
);

CREATE INDEX IF NOT EXISTS account_history_token_account_idx
    ON account_history (share_token, account_id);
CREATE INDEX IF NOT EXISTS account_history_token_observed_idx
    ON account_history (share_token, observed_at);

-- Append-only, same guarantee and same reasoning as verdicts in
-- migrations/0001_init.sql: a scan's account inventory at the time it
-- was observed should never be editable after the fact, by this server
-- or anyone with its credentials.
GRANT SELECT, INSERT ON account_history TO zerodock_app;
REVOKE UPDATE, DELETE ON account_history FROM zerodock_app;
GRANT USAGE, SELECT ON SEQUENCE account_history_id_seq TO zerodock_app;

COMMIT;

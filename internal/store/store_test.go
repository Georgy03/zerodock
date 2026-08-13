package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// testStore opens a Store against ZERODOCK_TEST_DATABASE_URL, skipping
// the test entirely if that isn't set — this package's whole point is
// talking to real Postgres, so there's no meaningful way to test it
// without one. Point ZERODOCK_TEST_DATABASE_URL at a throwaway database
// with every migration in migrations/ already applied (in order — in
// particular 0005_account_history.sql, which CreateVerdict now writes to
// on every call), connecting as
// zerodock_app (exactly the role/permissions the real server uses — see
// that migration for why testing against the OWNER role instead would
// hide exactly the bug this package most needs to catch: a query this
// code runs that zerodock_app isn't actually permitted to run).
//
// Each test truncates verdicts/subjects it touches via t.Cleanup, using a
// SEPARATE, unrestricted connection (TRUNCATE isn't something
// zerodock_app can do either, by design) — so tests can run repeatedly
// against the same long-lived database without interfering with each
// other.
func testStore(t *testing.T) *Store {
	t.Helper()
	dbURL := os.Getenv("ZERODOCK_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("ZERODOCK_TEST_DATABASE_URL not set; skipping tests that need a real Postgres instance")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := Open(ctx, dbURL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		// account_history rows FK-reference verdicts, so they have to go
		// first — deleting verdicts while account_history rows still
		// point at them would fail the FK constraint, not silently
		// cascade.
		s.pool.Exec(context.Background(), "DELETE FROM account_history")
		s.pool.Exec(context.Background(), "DELETE FROM verdicts")
		s.pool.Exec(context.Background(), "DELETE FROM share_links")
		s.Close()
	})
	return s
}

func sampleVerdict(scanID, accountID string) NewVerdict {
	return NewVerdict{
		ScannerVersion:       "v1.2.3",
		OrganizationVerified: true,
		NoOrganization:       true,
		AccountsListed:       []string{accountID},
		AccountsScanned:      []string{accountID},
		ScanID:               scanID,
		AccountID:            accountID,
		AttestedAt:           time.Now().UTC().Truncate(time.Millisecond),
		ScopeVerified:        true,
		TimeVerified:         true,
		RequestedRegions:     []string{"us-east-1"},
		ScannedRegions:       []string{"us-east-1"},
		ResultsSHA384:        "deadbeef",
		Checks:               json.RawMessage(`{}`),
		AttestationFormat:    "COSE_Sign1/ES384 (mock attester)",
		AttestationMock:      true,
		PCRs:                 json.RawMessage(`{"0":"aa","1":"bb","2":"cc"}`),
		AttestationRaw:       []byte{0x01, 0x02, 0x03},
	}
}

func TestCreateVerdict_IssuesTokenAndPersists(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	v, err := s.CreateVerdict(ctx, sampleVerdict("scan-create-1", "acct-create-1"))
	if err != nil {
		t.Fatalf("CreateVerdict: %v", err)
	}
	if v.ShareToken == "" {
		t.Error("expected a non-empty subject token")
	}
	if v.ID == 0 {
		t.Error("expected a non-zero ID")
	}
	if v.ReceivedAt.IsZero() {
		t.Error("expected ReceivedAt to be set")
	}
}

func TestCreateVerdict_SameAccountReusesToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	first, err := s.CreateVerdict(ctx, sampleVerdict("scan-reuse-1", "acct-reuse-1"))
	if err != nil {
		t.Fatalf("CreateVerdict (first): %v", err)
	}
	second, err := s.CreateVerdict(ctx, sampleVerdict("scan-reuse-2", "acct-reuse-1"))
	if err != nil {
		t.Fatalf("CreateVerdict (second): %v", err)
	}
	if first.ShareToken != second.ShareToken {
		t.Errorf("token changed across verdicts for the same account: %q vs %q", first.ShareToken, second.ShareToken)
	}
}

func TestCreateVerdict_DuplicateScanIDRejected(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, err := s.CreateVerdict(ctx, sampleVerdict("scan-dup-1", "acct-dup-1")); err != nil {
		t.Fatalf("CreateVerdict (first): %v", err)
	}
	_, err := s.CreateVerdict(ctx, sampleVerdict("scan-dup-1", "acct-dup-1"))
	if err != ErrDuplicateScan {
		t.Fatalf("CreateVerdict (duplicate) error = %v, want ErrDuplicateScan", err)
	}
}

func TestLatestVerdict_ReturnsNewestAttested(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	older := sampleVerdict("scan-latest-1", "acct-latest-1")
	older.AttestedAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	if _, err := s.CreateVerdict(ctx, older); err != nil {
		t.Fatalf("CreateVerdict (older): %v", err)
	}

	newer := sampleVerdict("scan-latest-2", "acct-latest-1")
	newer.AttestedAt = time.Now().UTC().Truncate(time.Millisecond)
	created, err := s.CreateVerdict(ctx, newer)
	if err != nil {
		t.Fatalf("CreateVerdict (newer): %v", err)
	}

	latest, err := s.LatestVerdict(ctx, created.ShareToken)
	if err != nil {
		t.Fatalf("LatestVerdict: %v", err)
	}
	if latest.ScanID != "scan-latest-2" {
		t.Errorf("LatestVerdict returned scan_id %q, want %q", latest.ScanID, "scan-latest-2")
	}
}

func TestLatestVerdict_UnknownTokenIsErrNotFound(t *testing.T) {
	s := testStore(t)
	_, err := s.LatestVerdict(context.Background(), "token-that-has-never-existed")
	if err != ErrNotFound {
		t.Fatalf("LatestVerdict error = %v, want ErrNotFound", err)
	}
}

func TestVerdictHistory_ReturnsAllNewestFirst(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	var token string
	for i, scanID := range []string{"scan-hist-1", "scan-hist-2", "scan-hist-3"} {
		nv := sampleVerdict(scanID, "acct-hist-1")
		nv.AttestedAt = time.Now().Add(time.Duration(i) * time.Minute).UTC().Truncate(time.Millisecond)
		v, err := s.CreateVerdict(ctx, nv)
		if err != nil {
			t.Fatalf("CreateVerdict %s: %v", scanID, err)
		}
		token = v.ShareToken
	}

	history, err := s.VerdictHistory(ctx, token, 0)
	if err != nil {
		t.Fatalf("VerdictHistory: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("got %d verdicts, want 3", len(history))
	}
	if history[0].ScanID != "scan-hist-3" || history[2].ScanID != "scan-hist-1" {
		t.Errorf("history not newest-first: got order %s, %s, %s", history[0].ScanID, history[1].ScanID, history[2].ScanID)
	}
}

func TestShareLinkStatus(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	v, err := s.CreateVerdict(ctx, sampleVerdict("scan-exists-1", "acct-exists-1"))
	if err != nil {
		t.Fatalf("CreateVerdict: %v", err)
	}

	exists, revoked, err := s.ShareLinkStatus(ctx, v.ShareToken)
	if err != nil {
		t.Fatalf("ShareLinkStatus: %v", err)
	}
	if !exists {
		t.Error("exists = false for a token that was just created")
	}
	if revoked {
		t.Error("revoked = true for a freshly created token")
	}

	exists, _, err = s.ShareLinkStatus(ctx, "token-that-has-never-existed")
	if err != nil {
		t.Fatalf("ShareLinkStatus: %v", err)
	}
	if exists {
		t.Error("exists = true for a token that was never created")
	}
}

// TestShareLinkStatus_Revoked confirms revoking a link (setting
// revoked_at — something only a privileged/admin role can do today; there
// is no revoke endpoint yet) is visible via ShareLinkStatus without
// touching the verdicts underneath it.
func TestShareLinkStatus_Revoked(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	v, err := s.CreateVerdict(ctx, sampleVerdict("scan-revoke-1", "acct-revoke-1"))
	if err != nil {
		t.Fatalf("CreateVerdict: %v", err)
	}

	// Revoking is an admin operation with no Store method yet (see the
	// comment on share_links.revoked_at in migrations/0001_init.sql) —
	// simulated here the same way a future admin tool would do it.
	if _, err := s.pool.Exec(ctx, "UPDATE share_links SET revoked_at = now() WHERE token = $1", v.ShareToken); err != nil {
		t.Fatalf("revoke share link (test setup): %v", err)
	}

	exists, revoked, err := s.ShareLinkStatus(ctx, v.ShareToken)
	if err != nil {
		t.Fatalf("ShareLinkStatus: %v", err)
	}
	if !exists || !revoked {
		t.Errorf("ShareLinkStatus = (exists=%v, revoked=%v), want (true, true)", exists, revoked)
	}

	// Revoking the link must not have touched the verdict itself.
	latest, err := s.LatestVerdict(ctx, v.ShareToken)
	if err != nil {
		t.Fatalf("LatestVerdict after revoke: %v", err)
	}
	if latest.ScanID != "scan-revoke-1" {
		t.Errorf("verdict data changed after revoking its share link: got scan_id %q", latest.ScanID)
	}
}

// TestVerdictsAreAppendOnly is the test that matters most: it confirms,
// against the REAL zerodock_app role and REAL Postgres grants (not just
// "our Go code never calls UPDATE/DELETE"), that this role genuinely
// cannot modify or erase a verdict once written.
func TestVerdictsAreAppendOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	v, err := s.CreateVerdict(ctx, sampleVerdict("scan-append-only-1", "acct-append-only-1"))
	if err != nil {
		t.Fatalf("CreateVerdict: %v", err)
	}

	_, err = s.pool.Exec(ctx, "UPDATE verdicts SET results_sha384 = 'tampered' WHERE id = $1", v.ID)
	if err == nil {
		t.Fatal("UPDATE on verdicts succeeded; the zerodock_app role must not be able to do this")
	}

	_, err = s.pool.Exec(ctx, "DELETE FROM verdicts WHERE id = $1", v.ID)
	if err == nil {
		t.Fatal("DELETE on verdicts succeeded; the zerodock_app role must not be able to do this")
	}
}

func strPtr(s string) *string { return &s }

// TestCreateVerdict_PopulatesAccountHistoryWithFirstSeenAndDrift exercises
// exactly the scenario internal/scope's own doc comment calls out: a
// second scan adds a new account with no scanner role yet, dropping
// coverage even though nothing about the two already-connected accounts
// changed. It checks both that account_history gets one row per listed
// account, correctly split into scanned/listed_unreachable, AND that
// first_seen_at is carried forward for accounts that already existed
// (not reset to the second scan's time).
func TestCreateVerdict_PopulatesAccountHistoryWithFirstSeenAndDrift(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	firstAttestedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	first := sampleVerdict("scan-drift-1", "acct-drift-mgmt")
	first.NoOrganization = false
	first.OrgID = strPtr("o-drift-example")
	first.AccountsListed = []string{"acct-drift-mgmt", "acct-drift-member"}
	first.AccountsScanned = []string{"acct-drift-mgmt", "acct-drift-member"}
	first.AttestedAt = firstAttestedAt

	v1, err := s.CreateVerdict(ctx, first)
	if err != nil {
		t.Fatalf("CreateVerdict (first scan): %v", err)
	}

	secondAttestedAt := time.Now().UTC().Truncate(time.Millisecond)
	second := sampleVerdict("scan-drift-2", "acct-drift-mgmt")
	second.NoOrganization = false
	second.OrgID = strPtr("o-drift-example")
	second.AccountsListed = []string{"acct-drift-mgmt", "acct-drift-member", "acct-drift-new"}
	second.AccountsScanned = []string{"acct-drift-mgmt", "acct-drift-member"} // acct-drift-new has no role yet
	second.AttestedAt = secondAttestedAt

	v2, err := s.CreateVerdict(ctx, second)
	if err != nil {
		t.Fatalf("CreateVerdict (second scan): %v", err)
	}
	if v1.ShareToken != v2.ShareToken {
		t.Fatalf("expected both scans (same account_id) to share a token, got %s and %s", v1.ShareToken, v2.ShareToken)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT verdict_id, account_id, status, first_seen_at, observed_at
		FROM account_history WHERE share_token = $1
		ORDER BY verdict_id, account_id
	`, v1.ShareToken)
	if err != nil {
		t.Fatalf("query account_history: %v", err)
	}
	defer rows.Close()

	type row struct {
		VerdictID               int64
		AccountID, Status       string
		FirstSeenAt, ObservedAt time.Time
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.VerdictID, &r.AccountID, &r.Status, &r.FirstSeenAt, &r.ObservedAt); err != nil {
			t.Fatalf("scan account_history row: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("account_history rows: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d account_history rows, want 5 (2 from the first scan + 3 from the second)", len(got))
	}

	for _, r := range got {
		switch {
		case r.VerdictID == v1.ID:
			if r.Status != "scanned" {
				t.Errorf("first scan account %s status = %s, want scanned", r.AccountID, r.Status)
			}
			if !r.FirstSeenAt.Equal(firstAttestedAt) {
				t.Errorf("first scan account %s first_seen_at = %v, want %v", r.AccountID, r.FirstSeenAt, firstAttestedAt)
			}
		case r.VerdictID == v2.ID && (r.AccountID == "acct-drift-mgmt" || r.AccountID == "acct-drift-member"):
			if r.Status != "scanned" {
				t.Errorf("second scan account %s status = %s, want scanned", r.AccountID, r.Status)
			}
			if !r.FirstSeenAt.Equal(firstAttestedAt) {
				t.Errorf("second scan account %s first_seen_at = %v, want carried forward from the first scan (%v), not reset", r.AccountID, r.FirstSeenAt, firstAttestedAt)
			}
		case r.VerdictID == v2.ID && r.AccountID == "acct-drift-new":
			if r.Status != "listed_unreachable" {
				t.Errorf("new account status = %s, want listed_unreachable (no scanner role yet)", r.Status)
			}
			if !r.FirstSeenAt.Equal(secondAttestedAt) {
				t.Errorf("new account first_seen_at = %v, want %v (this scan's own time — it wasn't seen before)", r.FirstSeenAt, secondAttestedAt)
			}
		default:
			t.Errorf("unexpected account_history row: verdict_id=%d account_id=%s", r.VerdictID, r.AccountID)
		}
	}
}

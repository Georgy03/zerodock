// Package store is the ONLY part of ZeroDock that talks to Postgres
// directly — every other package that needs a verdict persisted or read
// back goes through the small set of methods here, instead of writing
// its own SQL. Keeping that boundary narrow is what makes it possible to
// reason about the append-only guarantee at all: if nothing outside this
// file issues SQL against the verdicts table, then the REVOKE UPDATE,
// DELETE grant described in migrations/0001_init.sql (enforced by
// Postgres itself, not by this code) is the only thing standing between
// a verdict and being altered — and it can't be bypassed by mistake from
// somewhere else in the codebase, because there IS nowhere else.
package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Georgy03/zerodock/internal/scope"
)

// ErrNotFound is returned when a lookup by token or scan ID finds
// nothing — callers (the API layer) turn this into an HTTP 404.
var ErrNotFound = errors.New("not found")

// ErrDuplicateScan is returned by CreateVerdict when a verdict for this
// exact scan_id has already been stored. Submitting the same enclave
// report twice (e.g. a retried POST) is treated as "already done", not
// as an error worth failing loudly over — see how the API layer uses
// this.
var ErrDuplicateScan = errors.New("a verdict for this scan_id already exists")

// Store wraps a Postgres connection pool. Every method here assumes the
// schema in migrations/0001_init.sql has already been applied, and that
// it's connecting as the restricted zerodock_app role (see that file) —
// this package never issues a GRANT, REVOKE, CREATE TABLE, or anything
// else that only a migration should do.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres and confirms the connection actually works
// (via Ping) before returning — so a bad connection string or an
// unreachable database fails immediately at startup, not on the first
// request that happens to touch the database.
func Open(ctx context.Context, connString string) (*Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("open connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool. Call this once, when the server is
// shutting down.
func (s *Store) Close() {
	s.pool.Close()
}

// Verdict mirrors one row of the verdicts table — everything the API
// layer needs to render a JSON response, plus AttestationRaw, the exact
// bytes originally submitted.
type Verdict struct {
	ID                        int64
	ShareToken                string
	ScannerVersion            string
	OrganizationVerified      bool
	OrgID                     *string
	NoOrganization            bool
	OrganizationWarning       *string
	AccountsListed            []string
	AccountsScanned           []string
	SupabaseOrganizationID    *string
	ProjectsListed            []string
	ProjectsScanned           []string
	GCPOrganizationID         *string
	GCPProjectsListed         []string
	GCPProjectsScanned        []string
	AzureManagementGroups     []string
	AzureSubscriptionsListed  []string
	AzureSubscriptionsScanned []string
	ScanID                    string
	AccountID                 string
	AttestedAt                time.Time
	ReceivedAt                time.Time

	ScopeVerified bool
	ScopeWarning  *string
	TimeVerified  bool
	TimeWarning   *string

	RequestedRegions []string
	ScannedRegions   []string
	RegionsWarning   *string

	ResultsSHA384 string
	Checks        json.RawMessage

	AttestationFormat string
	AttestationMock   bool
	PCRs              json.RawMessage
	AttestationRaw    []byte
}

// NewVerdict is the input to CreateVerdict: everything about a verdict
// that comes from OUTSIDE this package (the submitted report plus the
// server's own verification outcome). ShareToken, ID, ReceivedAt, and
// CreatedAt are assigned inside CreateVerdict, not supplied here.
type NewVerdict struct {
	ScannerVersion            string
	OrganizationVerified      bool
	OrgID                     *string
	NoOrganization            bool
	OrganizationWarning       *string
	AccountsListed            []string
	AccountsScanned           []string
	SupabaseOrganizationID    *string
	ProjectsListed            []string
	ProjectsScanned           []string
	GCPOrganizationID         *string
	GCPProjectsListed         []string
	GCPProjectsScanned        []string
	AzureManagementGroups     []string
	AzureSubscriptionsListed  []string
	AzureSubscriptionsScanned []string
	ScanID                    string
	AccountID                 string
	AttestedAt                time.Time

	ScopeVerified bool
	ScopeWarning  *string
	TimeVerified  bool
	TimeWarning   *string

	RequestedRegions []string
	ScannedRegions   []string
	RegionsWarning   *string

	ResultsSHA384 string
	Checks        json.RawMessage

	AttestationFormat string
	AttestationMock   bool
	PCRs              json.RawMessage
	AttestationRaw    []byte
}

// CreateVerdict persists one verdict. It looks up (or, on an account's
// very first verdict, creates) that account's share link in the same
// database transaction as the insert, so a verdict is never left
// "orphaned" without a share_links row to hang off of.
//
// See the comment on share_links in migrations/0001_init.sql: creating a
// link here, on demand, with no vendor_id/label, is a placeholder for a
// real provisioning flow that doesn't exist yet — not the intended
// long-term story.
func (s *Store) CreateVerdict(ctx context.Context, nv NewVerdict) (Verdict, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Verdict{}, fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback is a no-op once Commit has already succeeded below — this
	// is just the standard "always have a rollback ready in case
	// anything between here and Commit returns early" pattern.
	defer tx.Rollback(ctx)

	token, err := getOrCreateShareLink(ctx, tx, nv.AccountID)
	if err != nil {
		return Verdict{}, err
	}

	// Fetched BEFORE inserting the new verdict below, so this is
	// genuinely the prior scan's attested inventory, not the one about
	// to be inserted.
	previousAccounts, err := previousAccountsSnapshot(ctx, tx, token)
	if err != nil {
		return Verdict{}, err
	}

	var v Verdict
	err = tx.QueryRow(ctx, `
		INSERT INTO verdicts (
			share_token, scanner_version,
			organization_verified, org_id, no_organization, organization_warning,
			accounts_listed, accounts_scanned,
			supabase_organization_id, projects_listed, projects_scanned,
			gcp_organization_id, gcp_projects_listed, gcp_projects_scanned,
			azure_management_groups, azure_subscriptions_listed, azure_subscriptions_scanned,
			scan_id, account_id, attested_at,
			scope_verified, scope_warning, time_verified, time_warning,
			requested_regions, scanned_regions, regions_warning,
			results_sha384, checks,
			attestation_format, attestation_mock, pcrs, attestation_raw
		) VALUES (
			$1, $2,
			$3, $4, $5, $6,
			$7, $8,
			$9, $10, $11,
			$12, $13, $14,
			$15, $16, $17,
			$18, $19, $20,
			$21, $22, $23,
			$24, $25, $26,
			$27, $28, $29, $30
		)
		RETURNING id, received_at
	`,
		token, nv.ScannerVersion,
		nv.OrganizationVerified, nv.OrgID, nv.NoOrganization, nv.OrganizationWarning,
		nv.AccountsListed, nv.AccountsScanned,
		nv.SupabaseOrganizationID, nv.ProjectsListed, nv.ProjectsScanned,
		nv.GCPOrganizationID, nv.GCPProjectsListed, nv.GCPProjectsScanned,
		nv.AzureManagementGroups, nv.AzureSubscriptionsListed, nv.AzureSubscriptionsScanned,
		nv.ScanID, nv.AccountID, nv.AttestedAt,
		nv.ScopeVerified, nv.ScopeWarning, nv.TimeVerified, nv.TimeWarning,
		nv.RequestedRegions, nv.ScannedRegions, nv.RegionsWarning,
		nv.ResultsSHA384, nv.Checks,
		nv.AttestationFormat, nv.AttestationMock, nv.PCRs, nv.AttestationRaw,
	).Scan(&v.ID, &v.ReceivedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return Verdict{}, ErrDuplicateScan
		}
		return Verdict{}, fmt.Errorf("insert verdict: %w", err)
	}

	currentAccounts := scope.AccountsSnapshot{Listed: nv.AccountsListed, Scanned: nv.AccountsScanned}
	for _, ev := range scope.Detect(previousAccounts, currentAccounts) {
		log.Printf("store: scope drift for share token %s: %+v", token, ev)
	}
	if err := insertAccountHistory(ctx, tx, token, v.ID, nv.OrgID, nv.AttestedAt, nv.AccountsListed, nv.AccountsScanned); err != nil {
		return Verdict{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Verdict{}, fmt.Errorf("commit transaction: %w", err)
	}

	v.ShareToken = token
	v.ScannerVersion = nv.ScannerVersion
	v.OrganizationVerified = nv.OrganizationVerified
	v.OrgID = nv.OrgID
	v.NoOrganization = nv.NoOrganization
	v.OrganizationWarning = nv.OrganizationWarning
	v.AccountsListed = nv.AccountsListed
	v.AccountsScanned = nv.AccountsScanned
	v.SupabaseOrganizationID = nv.SupabaseOrganizationID
	v.ProjectsListed = nv.ProjectsListed
	v.ProjectsScanned = nv.ProjectsScanned
	v.GCPOrganizationID = nv.GCPOrganizationID
	v.GCPProjectsListed = nv.GCPProjectsListed
	v.GCPProjectsScanned = nv.GCPProjectsScanned
	v.AzureManagementGroups = nv.AzureManagementGroups
	v.AzureSubscriptionsListed = nv.AzureSubscriptionsListed
	v.AzureSubscriptionsScanned = nv.AzureSubscriptionsScanned
	v.ScanID = nv.ScanID
	v.AccountID = nv.AccountID
	v.AttestedAt = nv.AttestedAt
	v.ScopeVerified = nv.ScopeVerified
	v.ScopeWarning = nv.ScopeWarning
	v.TimeVerified = nv.TimeVerified
	v.TimeWarning = nv.TimeWarning
	v.RequestedRegions = nv.RequestedRegions
	v.ScannedRegions = nv.ScannedRegions
	v.RegionsWarning = nv.RegionsWarning
	v.ResultsSHA384 = nv.ResultsSHA384
	v.Checks = nv.Checks
	v.AttestationFormat = nv.AttestationFormat
	v.AttestationMock = nv.AttestationMock
	v.PCRs = nv.PCRs
	v.AttestationRaw = nv.AttestationRaw
	return v, nil
}

// ShareLinkStatus reports whether a share token has ever been issued and,
// if so, whether it's been revoked. The API layer uses these two facts
// together to tell three situations apart: "this token was never valid"
// (404), "this token is valid but revoked" (410 — the link existed and
// meant something, but its owner killed it), and "this token is valid and
// live" (proceed to look up verdicts). Revoking a link never touches the
// verdicts underneath it — see the comment on share_links.revoked_at in
// migrations/0001_init.sql.
func (s *Store) ShareLinkStatus(ctx context.Context, token string) (exists, revoked bool, err error) {
	var revokedAt *time.Time
	err = s.pool.QueryRow(ctx, `SELECT revoked_at FROM share_links WHERE token = $1`, token).Scan(&revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("check share link status: %w", err)
	}
	return true, revokedAt != nil, nil
}

// verdictColumns lists the columns (in this exact order) that
// LatestVerdict/VerdictHistory select, and that scanVerdict below
// expects — kept as one named list so the two stay in sync by
// construction instead of by two people remembering to update both.
const verdictColumns = `
	id, share_token, COALESCE(scanner_version, ''),
	COALESCE(organization_verified, false), org_id, COALESCE(no_organization, false), organization_warning,
	COALESCE(accounts_listed, ARRAY[]::text[]), COALESCE(accounts_scanned, ARRAY[]::text[]),
	supabase_organization_id, COALESCE(projects_listed, ARRAY[]::text[]), COALESCE(projects_scanned, ARRAY[]::text[]),
	gcp_organization_id, COALESCE(gcp_projects_listed, ARRAY[]::text[]), COALESCE(gcp_projects_scanned, ARRAY[]::text[]),
	COALESCE(azure_management_groups, ARRAY[]::text[]), COALESCE(azure_subscriptions_listed, ARRAY[]::text[]), COALESCE(azure_subscriptions_scanned, ARRAY[]::text[]),
	scan_id, account_id, attested_at, received_at,
	scope_verified, scope_warning, time_verified, time_warning,
	requested_regions, scanned_regions, regions_warning,
	results_sha384, checks, attestation_format, attestation_mock,
	pcrs, attestation_raw
`

// LatestVerdict returns the most recently ATTESTED verdict for a token —
// see the comment on Verdict.AttestedAt vs ReceivedAt in
// migrations/0001_init.sql for why attested time, not arrival time, is
// what "latest" means here. This is about ORDERING among stored verdicts,
// not about freshness — an old-but-latest verdict is still returned; see
// internal/verify's note on authenticity vs freshness for why that's
// deliberate.
func (s *Store) LatestVerdict(ctx context.Context, token string) (Verdict, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT `+verdictColumns+`
		FROM verdicts
		WHERE share_token = $1
		ORDER BY attested_at DESC
		LIMIT 1
	`, token)

	v, err := scanVerdict(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Verdict{}, ErrNotFound
		}
		return Verdict{}, fmt.Errorf("query latest verdict: %w", err)
	}
	return v, nil
}

// defaultHistoryLimit and maxHistoryLimit bound how many rows
// VerdictHistory returns per call — an unbounded "give me everything"
// query against an append-only, ever-growing table is exactly the kind
// of thing that works fine in testing and then falls over in production.
const (
	defaultHistoryLimit = 100
	maxHistoryLimit     = 500
)

// VerdictHistory returns every verdict for a token, newest attested
// first, up to limit rows (defaultHistoryLimit if limit <= 0,
// maxHistoryLimit as a hard ceiling). An unknown token returns an empty
// slice, not an error — see ShareLinkStatus for how the API layer
// distinguishes that from "token never existed" or "token revoked".
func (s *Store) VerdictHistory(ctx context.Context, token string, limit int) ([]Verdict, error) {
	if limit <= 0 {
		limit = defaultHistoryLimit
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}

	rows, err := s.pool.Query(ctx, `
		SELECT `+verdictColumns+`
		FROM verdicts
		WHERE share_token = $1
		ORDER BY attested_at DESC
		LIMIT $2
	`, token, limit)
	if err != nil {
		return nil, fmt.Errorf("query verdict history: %w", err)
	}
	defer rows.Close()

	var out []Verdict
	for rows.Next() {
		v, err := scanVerdict(rows)
		if err != nil {
			return nil, fmt.Errorf("scan verdict row: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate verdict history: %w", err)
	}
	return out, nil
}

// scanner is satisfied by both pgx.Row (QueryRow's result) and pgx.Rows
// (Query's result, one row at a time) — letting LatestVerdict and
// VerdictHistory share exactly one column-scanning implementation instead
// of keeping two copies in sync by hand.
type scanner interface {
	Scan(dest ...any) error
}

func scanVerdict(row scanner) (Verdict, error) {
	var v Verdict
	err := row.Scan(
		&v.ID, &v.ShareToken, &v.ScannerVersion,
		&v.OrganizationVerified, &v.OrgID, &v.NoOrganization, &v.OrganizationWarning,
		&v.AccountsListed, &v.AccountsScanned,
		&v.SupabaseOrganizationID, &v.ProjectsListed, &v.ProjectsScanned,
		&v.GCPOrganizationID, &v.GCPProjectsListed, &v.GCPProjectsScanned,
		&v.AzureManagementGroups, &v.AzureSubscriptionsListed, &v.AzureSubscriptionsScanned,
		&v.ScanID, &v.AccountID, &v.AttestedAt, &v.ReceivedAt,
		&v.ScopeVerified, &v.ScopeWarning, &v.TimeVerified, &v.TimeWarning,
		&v.RequestedRegions, &v.ScannedRegions, &v.RegionsWarning,
		&v.ResultsSHA384, &v.Checks, &v.AttestationFormat, &v.AttestationMock,
		&v.PCRs, &v.AttestationRaw,
	)
	return v, err
}

// getOrCreateShareLink returns the existing share token for an account,
// or mints and stores a fresh one (vendor_id and label left NULL — see
// the comment on share_links in migrations/0001_init.sql) if this is
// that account's first verdict.
//
// The INSERT ... ON CONFLICT (account_id) DO UPDATE ... RETURNING token
// trick below is what makes this safe under concurrent requests for the
// SAME new account (two scans of a brand-new account landing at the same
// time): Postgres resolves the conflict atomically, so exactly one token
// ever gets stored for a given account_id no matter how many concurrent
// callers race to create it — the "losing" caller's DO UPDATE is a
// harmless no-op (it sets account_id to the value it already had) whose
// only real purpose is making RETURNING hand back the WINNING token.
// previousAccountsSnapshot fetches the most recently attested verdict's
// account inventory for a share token, for comparison against the
// verdict currently being inserted. Called before that insert happens,
// so "latest" here still means the PRIOR scan. No prior verdict (this
// token's very first scan) returns the zero value, which scope.Detect
// treats as "nothing to have drifted from yet."
func previousAccountsSnapshot(ctx context.Context, tx pgx.Tx, token string) (scope.AccountsSnapshot, error) {
	var listed, scanned []string
	err := tx.QueryRow(ctx, `
		SELECT accounts_listed, accounts_scanned FROM verdicts
		WHERE share_token = $1
		ORDER BY attested_at DESC
		LIMIT 1
	`, token).Scan(&listed, &scanned)
	if errors.Is(err, pgx.ErrNoRows) {
		return scope.AccountsSnapshot{}, nil
	}
	if err != nil {
		return scope.AccountsSnapshot{}, fmt.Errorf("look up previous accounts snapshot: %w", err)
	}
	return scope.AccountsSnapshot{Listed: listed, Scanned: scanned}, nil
}

// insertAccountHistory records one account_history row per account this
// verdict lists (whether or not the scan actually reached it), so later
// queries can answer "when was this account first seen" and "what did
// coverage look like at each past scan" without re-verifying every
// historical attestation. first_seen_at is carried forward from any
// prior row for the same (share_token, account_id) — an account that
// disappears and later reappears keeps its ORIGINAL first-seen time, not
// a reset one.
func insertAccountHistory(ctx context.Context, tx pgx.Tx, shareToken string, verdictID int64, orgID *string, attestedAt time.Time, listed, scanned []string) error {
	scannedSet := make(map[string]struct{}, len(scanned))
	for _, id := range scanned {
		scannedSet[id] = struct{}{}
	}

	for _, accountID := range listed {
		status := "listed_unreachable"
		if _, ok := scannedSet[accountID]; ok {
			status = "scanned"
		}

		var priorFirstSeen *time.Time
		err := tx.QueryRow(ctx, `
			SELECT MIN(first_seen_at) FROM account_history
			WHERE share_token = $1 AND account_id = $2
		`, shareToken, accountID).Scan(&priorFirstSeen)
		if err != nil {
			return fmt.Errorf("look up first-seen for account %s: %w", accountID, err)
		}
		firstSeen := attestedAt
		if priorFirstSeen != nil {
			firstSeen = *priorFirstSeen
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO account_history (share_token, verdict_id, org_id, account_id, status, first_seen_at, observed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, shareToken, verdictID, orgID, accountID, status, firstSeen, attestedAt)
		if err != nil {
			return fmt.Errorf("insert account_history row for account %s: %w", accountID, err)
		}
	}
	return nil
}

func getOrCreateShareLink(ctx context.Context, tx pgx.Tx, accountID string) (string, error) {
	candidate, err := newToken()
	if err != nil {
		return "", fmt.Errorf("generate share token: %w", err)
	}

	var token string
	err = tx.QueryRow(ctx, `
		INSERT INTO share_links (token, account_id)
		VALUES ($1, $2)
		ON CONFLICT (account_id) DO UPDATE SET account_id = EXCLUDED.account_id
		RETURNING token
	`, candidate, accountID).Scan(&token)
	if err != nil {
		return "", fmt.Errorf("get or create share link: %w", err)
	}
	return token, nil
}

// Onboarding is one vendor's in-progress AWS connection request: the
// tenant ID ZeroDock generated and the customer account ID the vendor
// supplied, so a later status poll knows which account's
// ZeroDockScannerRole to assume into.
type Onboarding struct {
	TenantID          string
	CustomerAccountID string
	CreatedAt         time.Time
}

// CreateOnboarding generates a new tenant ID and stores it alongside the
// customer's AWS account ID. The tenant ID is also the sts:ExternalId the
// generated CloudFormation command embeds, so it must be unguessable —
// the same random-token construction as share_links tokens.
func (s *Store) CreateOnboarding(ctx context.Context, customerAccountID string) (Onboarding, error) {
	tenantID, err := newToken()
	if err != nil {
		return Onboarding{}, fmt.Errorf("generate tenant id: %w", err)
	}

	var ob Onboarding
	err = s.pool.QueryRow(ctx, `
		INSERT INTO onboardings (tenant_id, customer_account_id)
		VALUES ($1, $2)
		RETURNING tenant_id, customer_account_id, created_at
	`, tenantID, customerAccountID).Scan(&ob.TenantID, &ob.CustomerAccountID, &ob.CreatedAt)
	if err != nil {
		return Onboarding{}, fmt.Errorf("create onboarding: %w", err)
	}
	return ob, nil
}

// GetOnboarding looks up a previously created onboarding by tenant ID.
// Returns ErrNotFound if no such tenant ID exists.
func (s *Store) GetOnboarding(ctx context.Context, tenantID string) (Onboarding, error) {
	var ob Onboarding
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, customer_account_id, created_at
		FROM onboardings
		WHERE tenant_id = $1
	`, tenantID).Scan(&ob.TenantID, &ob.CustomerAccountID, &ob.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Onboarding{}, ErrNotFound
	}
	if err != nil {
		return Onboarding{}, fmt.Errorf("get onboarding: %w", err)
	}
	return ob, nil
}

// newToken generates a random, unguessable share token: 16 random bytes,
// URL-safe base64 with no padding (so it drops cleanly into a URL path
// segment with no escaping needed).
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// isUniqueViolation reports whether err is a Postgres "unique_violation"
// (error code 23505) — the specific error CreateVerdict's INSERT raises
// when scan_id already exists, which we want to turn into the distinct
// ErrDuplicateScan rather than a generic failure.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// Package report defines the JSON shape of a ZeroDock scan report — the
// exact thing cmd/scanner produces at the end of a scan, and the exact
// thing internal/api's POST /v1/verdicts endpoint expects to receive.
//
// It's a SEPARATE package from both of those, and not just types living
// inside cmd/scanner, for one specific reason: the backend has to
// recompute the SAME SHA-384 hash cmd/scanner sealed inside the
// attestation's user_data, byte-for-byte, to confirm a submitted report
// actually matches what was attested (see internal/verify and the POST
// handler in internal/api). Go's encoding/json marshals struct fields in
// DECLARATION ORDER, so "byte-for-byte identical" requires both sides to
// marshal the literal same struct type — not two independently-written
// structs that merely have the same fields. Sharing one definition here
// makes that a compile-time guarantee instead of a "please don't let
// these drift" comment in two files.
package report

import (
	"time"

	"github.com/Georgy03/zerodock/internal/checks"
)

// CheckOutput bundles one check's descriptive info (Title, Tier) together
// with what it actually found (Result) — see checkOutput's original
// definition in cmd/scanner for the reasoning; it's unchanged here, just
// relocated so internal/api can decode the identical shape.
type CheckOutput struct {
	Title    string                   `json:"title"`
	Tier     checks.Tier              `json:"tier"`
	Result   checks.Result            `json:"result"`
	Accounts map[string]checks.Result `json:"accounts,omitempty"`
}

// AttestedContent is what actually gets hashed and sealed inside the
// attestation's user_data — NOT the whole Report below, just this. See
// the big comment on this shape's original home in cmd/scanner/main.go
// for the full reasoning (AccountID/ScopeVerified/TimeVerified/region
// scope are part of the CLAIM being attested, so they have to be inside
// the hash, not just printed alongside it; Timestamp deliberately is
// NOT included, since the signed document already carries its own).
//
// IMPORTANT: this struct's JSON serialization is a wire format AND a
// hash-input format. Changing field order, names, JSON tags, or omission
// behavior can make previously-issued attestations unverifiable. New fields
// therefore need an explicit compatibility rule: ScannerVersion uses
// omitempty so its absence reproduces legacy bytes exactly;
// any future change must provide the same kind of migration or introduce an
// explicit format version.
type AttestedContent struct {
	// ScannerVersion is the immutable Git tag whose pcrs.json describes
	// this binary. Omitempty preserves verification of reports issued before
	// this field existed; current scanners always set it.
	ScannerVersion       string                 `json:"scanner_version,omitempty"`
	OrganizationVerified bool                   `json:"organization_verified,omitempty"`
	OrgID                string                 `json:"org_id,omitempty"`
	NoOrganization       bool                   `json:"no_organization,omitempty"`
	OrganizationWarning  string                 `json:"organization_warning,omitempty"`
	AccountsListed       []string               `json:"accounts_listed,omitempty"`
	AccountsScanned      []string               `json:"accounts_scanned,omitempty"`
	AccountID            string                 `json:"account_id"`
	ScopeVerified        bool                   `json:"scope_verified"`
	ScopeWarning         string                 `json:"scope_warning,omitempty"`
	TimeVerified         bool                   `json:"time_verified"`
	TimeWarning          string                 `json:"time_warning,omitempty"`
	RequestedRegions     []string               `json:"requested_regions"`
	ScannedRegions       []string               `json:"scanned_regions"`
	RegionsWarning       string                 `json:"regions_warning,omitempty"`
	Checks               map[string]CheckOutput `json:"checks"`
}

// AttestationOutput is the small chunk of a report describing the signed
// proof. Doc holds the raw signed bytes, base64-encoded (base64 is a
// standard way to represent arbitrary binary data using only printable
// characters, which is necessary since it's embedded inside JSON text).
type AttestationOutput struct {
	Format string `json:"format"`
	Doc    string `json:"cose_sign1_base64"`
}

// Report is the ENTIRE thing cmd/scanner prints at the end of a run, and
// the entire thing a POST /v1/verdicts request body is expected to
// contain. AttestedContent is embedded (not a named field) so its JSON
// fields appear flattened at the top level here — account_id sits
// alongside scan_id and timestamp, not nested under an "attested_content"
// key — matching exactly how cmd/scanner always printed it, from before
// this package existed.
type Report struct {
	ScanID    string    `json:"scan_id"`
	Timestamp time.Time `json:"timestamp"`
	AttestedContent
	ResultsHash string             `json:"results_sha384"`
	Attestation *AttestationOutput `json:"attestation,omitempty"`
}

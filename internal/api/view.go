package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Georgy03/zerodock/internal/report"
	"github.com/Georgy03/zerodock/internal/store"
)

// verdictView is what GET /v1/share/{token} and .../history actually
// return — built from a store.Verdict, but with its JSONB columns
// decoded back into real JSON (rather than nested, double-encoded JSON
// strings) and the raw attestation bytes re-encoded as base64. The base64
// attestation IS included deliberately: the whole point of attesting in
// the first place is that a buyer's OWN browser-side verifier can
// independently re-check it, not just trust this server's word that it
// verified — this endpoint hands over exactly what a from-scratch
// verifier needs to do that.
type verdictView struct {
	ScannerVersion string    `json:"scanner_version,omitempty"`
	ScanID         string    `json:"scan_id"`
	AccountID      string    `json:"account_id"`
	AttestedAt     time.Time `json:"attested_at"`
	ReceivedAt     time.Time `json:"received_at"`

	ScopeVerified bool   `json:"scope_verified"`
	ScopeWarning  string `json:"scope_warning,omitempty"`
	TimeVerified  bool   `json:"time_verified"`
	TimeWarning   string `json:"time_warning,omitempty"`

	RequestedRegions []string `json:"requested_regions"`
	ScannedRegions   []string `json:"scanned_regions"`
	RegionsWarning   string   `json:"regions_warning,omitempty"`

	ResultsSHA384 string                        `json:"results_sha384"`
	Checks        map[string]report.CheckOutput `json:"checks"`

	Attestation verdictAttestationView `json:"attestation"`
}

type verdictAttestationView struct {
	Format string            `json:"format"`
	Mock   bool              `json:"mock"`
	PCRs   map[string]string `json:"pcrs"`
	Doc    string            `json:"cose_sign1_base64"`
}

// verdictToView decodes a store.Verdict's JSONB columns (stored as
// json.RawMessage — opaque bytes as far as package store is concerned)
// into the actual structured JSON this endpoint returns.
func verdictToView(v store.Verdict) (verdictView, error) {
	var checksOut map[string]report.CheckOutput
	if err := json.Unmarshal(v.Checks, &checksOut); err != nil {
		return verdictView{}, fmt.Errorf("decode stored checks: %w", err)
	}

	var pcrsOut map[string]string
	if err := json.Unmarshal(v.PCRs, &pcrsOut); err != nil {
		return verdictView{}, fmt.Errorf("decode stored PCRs: %w", err)
	}

	return verdictView{
		ScannerVersion:   v.ScannerVersion,
		ScanID:           v.ScanID,
		AccountID:        v.AccountID,
		AttestedAt:       v.AttestedAt,
		ReceivedAt:       v.ReceivedAt,
		ScopeVerified:    v.ScopeVerified,
		ScopeWarning:     derefOrEmpty(v.ScopeWarning),
		TimeVerified:     v.TimeVerified,
		TimeWarning:      derefOrEmpty(v.TimeWarning),
		RequestedRegions: v.RequestedRegions,
		ScannedRegions:   v.ScannedRegions,
		RegionsWarning:   derefOrEmpty(v.RegionsWarning),
		ResultsSHA384:    v.ResultsSHA384,
		Checks:           checksOut,
		Attestation: verdictAttestationView{
			Format: v.AttestationFormat,
			Mock:   v.AttestationMock,
			PCRs:   pcrsOut,
			Doc:    base64.StdEncoding.EncodeToString(v.AttestationRaw),
		},
	}, nil
}

func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

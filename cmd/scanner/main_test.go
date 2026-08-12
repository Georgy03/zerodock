package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
)

// TestAttestedContentIncludesTimeVerificationState protects the report's
// honesty contract: a report must not be able to change from an untrusted
// timestamp to a trusted one (or hide why time was untrusted) without
// changing ResultsHash and invalidating its attestation.
func TestAttestedContentIncludesTimeVerificationState(t *testing.T) {
	base := report.AttestedContent{
		ScannerVersion: "v1.2.3",
		AccountID:      "123456789012",
		ScopeVerified:  true,
		TimeVerified:   false,
		TimeWarning:    "could not read timestamp from attestation document",
		Checks:         map[string]report.CheckOutput{},
	}

	baseHash := hashAttestedContentForTest(t, base)

	trusted := base
	trusted.TimeVerified = true
	trusted.TimeWarning = ""
	if got := hashAttestedContentForTest(t, trusted); got == baseHash {
		t.Fatal("changing time_verified did not change the attested hash")
	}

	differentReason := base
	differentReason.TimeWarning = "NSM timestamp unavailable"
	if got := hashAttestedContentForTest(t, differentReason); got == baseHash {
		t.Fatal("changing time_warning did not change the attested hash")
	}
}

func TestAggregateAccountResultsPreservesWorstStatusAndAccountIdentity(t *testing.T) {
	result := aggregateAccountResults(map[string]checks.Result{
		"222222222222": {Status: checks.StatusError, Findings: []string{"AccessDenied"}, Count: 1},
		"111111111111": {Status: checks.StatusFail, Findings: []string{"unencrypted volume vol-1"}, Count: 2},
	})

	if result.Status != checks.StatusError {
		t.Fatalf("status = %q, want error", result.Status)
	}
	if result.Count != 3 {
		t.Fatalf("count = %d, want 3", result.Count)
	}
	wantFindings := []string{
		"account 111111111111: unencrypted volume vol-1",
		"account 222222222222: AccessDenied",
	}
	if len(result.Findings) != len(wantFindings) {
		t.Fatalf("findings = %v, want %v", result.Findings, wantFindings)
	}
	for index := range wantFindings {
		if result.Findings[index] != wantFindings[index] {
			t.Fatalf("findings = %v, want %v", result.Findings, wantFindings)
		}
	}
}

// ScannerVersion selects the independently published PCR manifest. It must be
// sealed into user_data so an API cannot swap the tag after attestation.
func TestAttestedContentIncludesScannerVersion(t *testing.T) {
	base := report.AttestedContent{
		ScannerVersion: "v1.2.3",
		AccountID:      "123456789012",
		Checks:         map[string]report.CheckOutput{},
	}
	otherRelease := base
	otherRelease.ScannerVersion = "v1.2.4"

	if hashAttestedContentForTest(t, base) == hashAttestedContentForTest(t, otherRelease) {
		t.Fatal("changing scanner_version did not change the attested hash")
	}
}

func TestAttestedContentIncludesOrganizationCoverage(t *testing.T) {
	base := report.AttestedContent{
		ScannerVersion:       "v1.2.3",
		OrganizationVerified: true,
		OrgID:                "o-example",
		AccountsListed:       []string{"111111111111", "222222222222"},
		AccountsScanned:      []string{"111111111111"},
		AccountID:            "111111111111",
		Checks:               map[string]report.CheckOutput{},
	}
	baseHash := hashAttestedContentForTest(t, base)

	fullyScanned := base
	fullyScanned.AccountsScanned = []string{"111111111111", "222222222222"}
	if hashAttestedContentForTest(t, fullyScanned) == baseHash {
		t.Fatal("changing accounts_scanned did not change the attested hash")
	}

	differentOrg := base
	differentOrg.OrgID = "o-other"
	if hashAttestedContentForTest(t, differentOrg) == baseHash {
		t.Fatal("changing org_id did not change the attested hash")
	}

	noOrganization := base
	noOrganization.OrganizationVerified = true
	noOrganization.OrgID = ""
	noOrganization.NoOrganization = true
	noOrganization.AccountsListed = []string{"111111111111"}
	if hashAttestedContentForTest(t, noOrganization) == baseHash {
		t.Fatal("changing to the explicit no-organization fallback did not change the attested hash")
	}
}

func hashAttestedContentForTest(t *testing.T, content report.AttestedContent) string {
	t.Helper()
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal attested content: %v", err)
	}
	sum := sha512.Sum384(encoded)
	return hex.EncodeToString(sum[:])
}

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"testing"

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

func hashAttestedContentForTest(t *testing.T, content report.AttestedContent) string {
	t.Helper()
	encoded, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal attested content: %v", err)
	}
	sum := sha512.Sum384(encoded)
	return hex.EncodeToString(sum[:])
}

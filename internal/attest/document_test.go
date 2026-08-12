package attest

import (
	"crypto/rand"
	"time"

	"testing"
)

// TestExtractTimestamp_MatchesMockAttesterClock confirms ExtractTimestamp
// correctly reads back the same timestamp MockAttester just stamped a
// document with — the round trip this codebase now depends on for getting
// a trustworthy "now" without calling time.Now() directly everywhere (see
// trustedNow in cmd/scanner/main.go).
func TestExtractTimestamp_MatchesMockAttesterClock(t *testing.T) {
	attester, err := NewMockAttester()
	if err != nil {
		t.Fatalf("NewMockAttester: %v", err)
	}

	before := time.Now()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	doc, err := attester.Attest([]byte("time-sync"), nonce)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	after := time.Now()

	ts, err := ExtractTimestamp(doc)
	if err != nil {
		t.Fatalf("ExtractTimestamp: %v", err)
	}

	// The extracted timestamp should fall between "just before" and
	// "just after" the Attest() call — not exactly equal, since the
	// document's Timestamp field only has millisecond resolution and
	// before/after are measured slightly outside the call itself.
	if ts.Before(before.Add(-time.Second)) || ts.After(after.Add(time.Second)) {
		t.Errorf("ExtractTimestamp() = %v, want between %v and %v", ts, before, after)
	}
}

// TestExtractTimestampAcceptsTaggedAndUntaggedSign1 checks the two COSE_Sign1
// wrappers we must support. MockAttester produces the canonical tagged form;
// removing its one-byte tag gives the untagged form returned by real NSM
// documents in our integration test. The signed payload itself is unchanged.
func TestExtractTimestampAcceptsTaggedAndUntaggedSign1(t *testing.T) {
	attester, err := NewMockAttester()
	if err != nil {
		t.Fatalf("NewMockAttester: %v", err)
	}

	tagged, err := attester.Attest([]byte("time-sync"), []byte("nonce"))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if len(tagged) == 0 || tagged[0] != 0xd2 {
		t.Fatalf("MockAttester document starts %x, want CBOR tag 18 (d2)", tagged)
	}

	for _, tc := range []struct {
		name string
		doc  []byte
	}{
		{name: "tagged", doc: tagged},
		{name: "untagged", doc: tagged[1:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := ExtractTimestamp(tc.doc)
			if err != nil {
				t.Fatalf("ExtractTimestamp: %v", err)
			}
			if ts.IsZero() {
				t.Fatal("ExtractTimestamp returned a zero timestamp")
			}
		})
	}
}

// TestExtractTimestamp_RejectsGarbage confirms garbage input fails
// loudly with an error instead of silently returning some zero-ish or
// misleading time value.
func TestExtractTimestamp_RejectsGarbage(t *testing.T) {
	_, err := ExtractTimestamp([]byte("this is not a COSE_Sign1 document"))
	if err == nil {
		t.Fatal("expected an error for garbage input, got nil")
	}
}

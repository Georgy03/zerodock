package verify

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/Georgy03/zerodock/internal/attest"
)

func mustMockDoc(t *testing.T, userData []byte) []byte {
	t.Helper()
	attester, err := attest.NewMockAttester()
	if err != nil {
		t.Fatalf("NewMockAttester: %v", err)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	doc, err := attester.Attest(userData, nonce)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	return doc
}

// TestVerify_MockDocumentRequiresAllowMock is the central policy test:
// a MockAttester document is internally consistent (real signature, real
// self-signed chain) but must never be accepted as a genuine hardware
// attestation unless the caller explicitly opts in.
func TestVerify_MockDocumentRequiresAllowMock(t *testing.T) {
	doc := mustMockDoc(t, []byte("results-hash"))

	t.Run("rejected by default", func(t *testing.T) {
		_, err := Verify(doc, Options{AllowMock: false})
		if !errors.Is(err, ErrMockNotAllowed) {
			t.Fatalf("Verify() error = %v, want ErrMockNotAllowed", err)
		}
	})

	t.Run("accepted when explicitly allowed", func(t *testing.T) {
		outcome, err := Verify(doc, Options{AllowMock: true})
		if err != nil {
			t.Fatalf("Verify() error = %v, want nil", err)
		}
		if !outcome.Mock {
			t.Error("outcome.Mock = false, want true for a MockAttester document")
		}
		if len(outcome.PCRs) != 3 {
			t.Errorf("got %d PCRs, want 3", len(outcome.PCRs))
		}
		if string(outcome.UserData) != "results-hash" {
			t.Errorf("UserData = %q, want %q", outcome.UserData, "results-hash")
		}
	})
}

// TestVerify_RejectsTamperedPayload confirms that flipping a single byte
// of the signed document (simulating a submission tampered with after
// signing) breaks signature verification, rather than being silently
// accepted.
func TestVerify_RejectsTamperedPayload(t *testing.T) {
	doc := mustMockDoc(t, []byte("results-hash"))

	tampered := append([]byte(nil), doc...)
	// Flip a byte roughly in the middle of the document, which — for a
	// CBOR/COSE structure this size — reliably lands inside the signed
	// payload rather than in framing bytes that might happen to still
	// parse.
	mid := len(tampered) / 2
	tampered[mid] ^= 0xFF

	_, err := Verify(tampered, Options{AllowMock: true})
	if err == nil {
		t.Fatal("Verify() on tampered document returned nil error, want a verification failure")
	}
}

// TestVerify_RejectsGarbage confirms input that isn't a COSE_Sign1
// document at all fails cleanly.
func TestVerify_RejectsGarbage(t *testing.T) {
	_, err := Verify([]byte("not an attestation document"), Options{AllowMock: true})
	if err == nil {
		t.Fatal("Verify() on garbage input returned nil error, want a decode failure")
	}
}

package attest_test

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/Georgy03/zerodock/internal/verify"
)

func TestGoVerifierAcceptsSharedRealNSMDocument(t *testing.T) {
	rawDocument, err := os.ReadFile("../../testdata/real-nsm-cose.b64")
	if err != nil {
		t.Fatalf("read shared real-NSM fixture: %v", err)
	}
	signedDoc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawDocument)))
	if err != nil {
		t.Fatalf("decode attestation: %v", err)
	}

	if _, err := verify.Verify(signedDoc, verify.Options{}); err != nil {
		t.Fatalf("Go verifier rejected the real NSM fixture: %v", err)
	}
}

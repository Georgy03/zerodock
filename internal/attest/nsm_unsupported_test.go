//go:build !linux

package attest

import (
	"strings"
	"testing"
)

func TestNewNSMAttesterUnsupportedPlatform(t *testing.T) {
	attester, err := NewNSMAttester()
	if err == nil {
		t.Fatal("NewNSMAttester() error = nil, want non-nil")
	}
	if attester != nil {
		t.Fatalf("NewNSMAttester() attester = %#v, want nil", attester)
	}
	if !strings.Contains(err.Error(), "AWS Nitro Enclave") {
		t.Fatalf("NewNSMAttester() error = %q, want a clear Nitro Enclave error", err)
	}
}

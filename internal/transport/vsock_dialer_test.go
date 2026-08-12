package transport

import (
	"context"
	"strings"
	"testing"
)

// TestVsockDialer_UnknownHostFailsFastWithClearError is the single most
// important test in this package. The #1 way a real enclave run goes
// wrong is a check calling an AWS hostname that isn't in
// hostnameToVsockPort — without this check, that failure mode is "the
// whole scan hangs forever with no error", which is nearly impossible to
// debug from inside an enclave with no console output. This confirms the
// dial fails IMMEDIATELY (no real connection attempt at all) with a
// message that names the actual problem.
func TestVsockDialer_UnknownHostFailsFastWithClearError(t *testing.T) {
	d := NewVsockDialer()

	_, err := d.DialContext(context.Background(), "tcp", "unknown-service.us-east-1.amazonaws.com:443")
	if err == nil {
		t.Fatal("expected an error for an unlisted host, got nil")
	}
	if !strings.Contains(err.Error(), "unknown-service.us-east-1.amazonaws.com") {
		t.Errorf("error should name the unresolved host, got: %v", err)
	}
	if !strings.Contains(err.Error(), "endpoints.go") {
		t.Errorf("error should point at endpoints.go so the fix is obvious, got: %v", err)
	}
}

// TestVsockDialer_HostWithoutPortStillLooksUp confirms addr values with
// no ":port" suffix (SplitHostPort would fail on these) still resolve
// correctly by falling back to treating the whole string as the host.
func TestVsockDialer_HostWithoutPortStillLooksUp(t *testing.T) {
	d := NewVsockDialer()

	_, err := d.DialContext(context.Background(), "tcp", "iam.amazonaws.com")
	// We expect SOME error here (there's no real vsock device in this
	// test environment), but it must NOT be the "unknown host" error —
	// that would mean the lookup itself failed, not just the dial.
	if err == nil {
		t.Fatal("expected a dial error (no real vsock device in tests), got nil")
	}
	if strings.Contains(err.Error(), "no vsock port configured") {
		t.Errorf("iam.amazonaws.com should have resolved to a known port; got lookup failure: %v", err)
	}
}

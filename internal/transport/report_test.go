package transport

import (
	"context"
	"strings"
	"testing"
)

// TestSendReport_SurfacesDialErrorClearly confirms a failed connection to
// the parent's report collector comes back as a clear, wrapped error
// (naming what step failed) rather than a bare, unhelpful one — this is
// what cmd/scanner/main.go's deliverReport retries against, so the error
// it eventually reports on final failure needs to actually say something
// useful.
func TestSendReport_SurfacesDialErrorClearly(t *testing.T) {
	dialer := NewVsockDialer()

	err := SendReport(context.Background(), dialer, []byte(`{"scan_id":"test"}`))
	if err == nil {
		t.Fatal("expected an error (no real vsock device in tests), got nil")
	}
	if !strings.Contains(err.Error(), "connect to parent report collector") {
		t.Errorf("error should say what step failed, got: %v", err)
	}
}

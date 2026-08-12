package transport

import (
	"context"
	"fmt"
)

// SendReport delivers the enclave's finished JSON report to the parent
// instance's report collector (see deploy/collect-report.py): dial the
// parent on VsockPortReport, write the whole payload, close the
// connection. That's it — there's no acknowledgement or response to wait
// for, because the collector just reads until the enclave closes its end
// (EOF), the same way FetchCredentials reads until the PARENT closes its
// end in the other direction.
//
// This is a single attempt with no retry logic — retrying belongs to the
// CALLER (see deliverReport in cmd/scanner/main.go), not here, because
// only the caller knows how many attempts make sense and what "give up"
// should mean for the program as a whole.
func SendReport(ctx context.Context, dialer *VsockDialer, payload []byte) error {
	conn, err := dialer.dialPort(ctx, VsockPortReport)
	if err != nil {
		return fmt.Errorf("connect to parent report collector: %w", err)
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write report to parent: %w", err)
	}

	return nil
}

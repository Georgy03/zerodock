package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/mdlayher/vsock"
)

// hostVsockContextID is the vsock "Context ID" (vsock's equivalent of an
// IP address) that always means "the parent EC2 instance hosting this
// enclave" — every Nitro Enclave uses this same fixed value, so unlike a
// normal IP address, it never needs to be looked up or configured.
const hostVsockContextID = 3

// VsockDialer opens connections over vsock instead of a real network
// interface. This is the ONLY way an AWS Nitro Enclave can reach the
// outside world at all — an enclave has no network card, no IP address,
// and no DNS resolver. Every byte it sends has to go through vsock to the
// parent instance, where a "vsock-proxy" process (see deploy/start-proxies.sh)
// relays it on to the real internet over the parent's normal network.
type VsockDialer struct{}

// NewVsockDialer builds a VsockDialer. There's no setup to do — unlike
// TCPDialer, there's no connection pool or timeout config to configure
// here, because vsock connections in this program are always short-lived,
// one-per-request affairs to a known, fixed set of ports.
func NewVsockDialer() *VsockDialer {
	return &VsockDialer{}
}

// DialContext is what makes VsockDialer a drop-in replacement for a normal
// dialer, even though vsock doesn't work anything like TCP/DNS
// underneath. Here's the trick: an *http.Client asks its dialer to
// connect to something like "ec2.us-east-1.amazonaws.com:443" — a normal
// hostname and port. We can't dial that directly (there's no DNS inside
// an enclave), so instead we:
//
//  1. Pull just the HOSTNAME back out of that address (throwing away the
//     ":443", which doesn't matter here — see below).
//  2. Look that hostname up in our fixed hostnameToVsockPort table to find
//     which vsock port reaches it.
//  3. Dial the parent instance (context ID 3) on THAT port instead.
//
// If step 2 fails — the hostname isn't in our table — the connection
// attempt fails immediately with a clear error, rather than hanging. THIS
// is the #1 thing to check if a scan run inside the enclave just hangs
// forever with no error: it usually means a check is calling an AWS
// endpoint whose hostname isn't listed in endpoints.go (and therefore
// isn't allowlisted in deploy/vsock-proxy.yaml or started by
// deploy/start-proxies.sh either).
//
// Why we can safely ignore the ":443" port from addr: every AWS API this
// scanner calls uses HTTPS, and each hostname in our table maps 1:1 to
// exactly one vsock port already, so the port number system doesn't need
// to distinguish between different TCP ports on the SAME hostname the way
// a general-purpose dialer would.
func (d *VsockDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// addr didn't include a port at all — just use it as-is.
		host = addr
	}

	port, ok := hostnameToVsockPort[host]
	if !ok {
		return nil, fmt.Errorf(
			"vsock: no vsock port configured for host %q — add it to internal/transport/endpoints.go, "+
				"deploy/vsock-proxy.yaml, and deploy/start-proxies.sh", host)
	}

	return d.dialPort(ctx, port)
}

// dialPort opens a raw vsock connection to the given port on the parent
// instance, honoring ctx cancellation. The underlying vsock.Dial call has
// no built-in support for a context, so we run it in a goroutine and race
// it against ctx.Done() — a standard pattern for adding cancellation to a
// blocking call that doesn't natively support it.
func (d *VsockDialer) dialPort(ctx context.Context, port uint32) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)

	go func() {
		conn, err := vsock.Dial(hostVsockContextID, port, nil)
		resultCh <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return nil, fmt.Errorf("vsock: dial parent (CID %d) port %d: %w", hostVsockContextID, port, res.err)
		}
		return res.conn, nil
	}
}

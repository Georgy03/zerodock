// Package transport supplies the network plumbing an AWS SDK HTTP client
// needs, in two interchangeable flavors:
//
//   - TCPDialer: an ordinary internet connection. Used when the scanner is
//     running as a normal program (your laptop, a plain EC2 instance) with
//     real network access.
//   - VsockDialer: a connection through "vsock" — the special, walled-off
//     channel a Nitro Enclave uses to talk to its PARENT EC2 instance,
//     since an enclave has no network interface of its own at all. Used
//     when the scanner is running inside the enclave.
//
// Both implement the same small Dialer interface, so the rest of the
// program (specifically, the *http.Client built in http_client.go) never
// needs to know or care which one it's using — swapping one for the other
// is a one-line change in cmd/scanner/main.go.
package transport

import (
	"context"
	"net"
)

// Dialer opens outgoing network connections. It intentionally mirrors the
// shape Go's own net.Dialer already uses (a DialContext method), because
// that's exactly the shape http.Transport.DialContext expects — so
// whichever Dialer we build gets plugged straight into an *http.Client with
// no adapter code needed.
type Dialer interface {
	// DialContext opens a connection. network and addr have the same
	// meaning they do for net.Dialer (e.g. network="tcp",
	// addr="ec2.us-east-1.amazonaws.com:443") — VsockDialer reads the
	// HOSTNAME out of addr to decide which vsock port to use, even though
	// the connection it opens isn't a TCP connection at all.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

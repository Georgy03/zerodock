package transport

import (
	"context"
	"net"
	"time"
)

// TCPDialer is the "normal" dialer: a thin wrapper around Go's standard
// net.Dialer, making real internet connections. Use this whenever the
// scanner has a real network interface available — i.e. everywhere except
// inside a running Nitro Enclave.
type TCPDialer struct {
	dialer net.Dialer
}

// NewTCPDialer builds a TCPDialer with a sane connection timeout, so a
// single unreachable host can't hang the whole scan forever.
func NewTCPDialer() *TCPDialer {
	return &TCPDialer{
		dialer: net.Dialer{Timeout: 10 * time.Second},
	}
}

// DialContext just forwards to the standard library — there's nothing
// enclave-specific happening here at all.
func (d *TCPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

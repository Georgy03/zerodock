package transport

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// NewHTTPClient builds the *http.Client every AWS SDK client in this
// program uses to make requests, wired up with:
//
//  1. dialer — decides HOW connections get opened: a normal internet
//     connection (TCPDialer) or a vsock hop through the enclave's parent
//     instance (VsockDialer). This is the only thing that differs between
//     "running as a normal program" and "running inside an enclave" — the
//     AWS SDK code, and every check, is completely unaware of the
//     difference.
//  2. our embedded Amazon root certificates — NOT whatever the operating
//     system happens to trust. See rootcerts.go for why that matters.
func NewHTTPClient(dialer Dialer) (*http.Client, error) {
	rootCAs, err := NewRootCAPool()
	if err != nil {
		return nil, fmt.Errorf("build root CA pool: %w", err)
	}

	transport := &http.Transport{
		// This is the plug point: whatever Dialer we were given is what
		// actually opens every outgoing connection this client makes.
		DialContext: dialer.DialContext,

		TLSClientConfig: &tls.Config{
			// MinVersion is set explicitly rather than left at Go's
			// default, so a future change to Go's default minimum TLS
			// version can't silently loosen what this client accepts.
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},

		// A generous but finite timeout for the TLS handshake itself,
		// separate from the dialer's own connect timeout — so a peer
		// that accepts the TCP/vsock connection but then stalls during
		// the handshake still can't hang the client forever.
		TLSHandshakeTimeout: 15 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

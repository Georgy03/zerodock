package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Credentials is the JSON shape the parent instance is expected to send
// down the credentials vsock connection — see FetchCredentials below and
// deploy/serve-credentials.py for the parent-side half of this contract.
//
// SECURITY NOTE ON WHY THIS IS SAFE: this JSON blob (containing a live AWS
// secret key) travels over vsock, which is a private, point-to-point
// channel that exists ONLY between this enclave and its own parent
// instance — it is not a network route any other machine, container, or
// process can observe or inject into. Separately, and just as
// importantly: every AWS API call this scanner makes is itself a TLS
// connection that terminates INSIDE the enclave (see http_client.go and
// rootcerts.go) — the parent instance's vsock-proxy only ever relays
// opaque encrypted TLS bytes it cannot read or modify. So even though the
// parent hands the enclave its AWS credentials, the parent can neither
// read what the enclave subsequently does with them (the API requests)
// nor tamper with what comes back (the API responses). Compromising the
// parent gets you a copy of the temporary credentials, not a way to see
// or alter a single AWS API call this scanner makes.
type Credentials struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	Expiration      time.Time `json:"expiration"`
}

// FetchCredentials connects to the parent instance on the dedicated
// credentials port (VsockPortCredentials) ONCE, at enclave startup, reads
// whatever the parent sends until it closes the connection, and parses it
// as a Credentials JSON blob.
//
// This deliberately does the simplest thing that works for week 3: one
// connection, read-to-EOF, parse. A production version would eventually
// want to re-fetch before the credentials in Expiration run out (AWS
// temporary credentials are typically only valid for up to a few hours) —
// that's future work, not something this single-scan-and-exit build needs
// yet.
func FetchCredentials(ctx context.Context, dialer *VsockDialer) (Credentials, error) {
	conn, err := dialer.dialPort(ctx, VsockPortCredentials)
	if err != nil {
		return Credentials{}, fmt.Errorf("connect to parent for credentials: %w", err)
	}
	defer conn.Close()

	raw, err := io.ReadAll(conn)
	if err != nil {
		return Credentials{}, fmt.Errorf("read credentials from parent: %w", err)
	}

	return parseCredentials(raw)
}

// parseCredentials is split out from FetchCredentials so the parsing and
// validation logic can be unit tested directly, with plain []byte input,
// instead of needing a real (or fake) vsock connection to exercise it.
func parseCredentials(raw []byte) (Credentials, error) {
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		return Credentials{}, fmt.Errorf("parse credentials JSON from parent: %w", err)
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return Credentials{}, fmt.Errorf("credentials from parent are missing access_key_id or secret_access_key")
	}

	return creds, nil
}

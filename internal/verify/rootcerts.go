package verify

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// trustedNitroRootPEM is the real, official AWS Nitro Enclaves root
// certificate, downloaded from
// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// (the address AWS's own attestation documentation points to) and
// embedded at compile time via go:embed — the same reasoning as
// internal/transport/rootcerts.go: a trust anchor that can be swapped by
// editing a file on a running system isn't a trust anchor.
//
// This is the ONLY certificate this server trusts as "real hardware
// attestation". Anything that verifies but chains to a DIFFERENT root
// (e.g. one of MockAttester's freshly-generated throwaway roots) is
// necessarily a mock attestation — see Verify's Mock field.
//
//go:embed rootcerts/AWSNitroEnclavesRootG1.pem
var trustedNitroRootPEM []byte

// trustedNitroRoot parses trustedNitroRootPEM once, at package load, into
// both a ready-to-use *x509.Certificate (so Verify can compare
// fingerprints without reparsing on every request) and a *x509.CertPool
// (which the standard library's chain verification needs).
var (
	trustedNitroRoot     *x509.Certificate
	trustedNitroRootPool *x509.CertPool
)

func init() {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustedNitroRootPEM) {
		// This can only happen from a build-time mistake (a corrupted or
		// missing embedded file) — not from anything a caller sends us —
		// so panicking at package load is the right response: better to
		// fail loudly the moment the server starts than to silently
		// accept every attestation as "untrusted" from then on.
		panic("internal/verify: embedded AWS Nitro root certificate failed to parse")
	}
	trustedNitroRootPool = pool

	cert, err := parseSinglePEMCert(trustedNitroRootPEM)
	if err != nil {
		panic(fmt.Sprintf("internal/verify: embedded AWS Nitro root certificate failed to parse: %s", err))
	}
	trustedNitroRoot = cert
}

// parseSinglePEMCert decodes a PEM file expected to contain exactly one
// certificate.
func parseSinglePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("expected exactly one PEM block, found trailing data")
	}
	return x509.ParseCertificate(block.Bytes)
}

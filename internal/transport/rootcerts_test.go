package transport

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestNewRootCAPool_LoadsAllRoots confirms every embedded PEM file
// parses successfully and ends up in the pool. x509.CertPool doesn't
// expose a simple "how many certs are in here" count, so we check via
// Subjects() (deprecated but still functional and the simplest way to get
// a count without re-parsing the PEMs ourselves) as a basic sanity check
// that all four made it in, not zero or some smaller number.
func TestNewRootCAPool_LoadsAllRoots(t *testing.T) {
	pool, err := NewRootCAPool()
	if err != nil {
		t.Fatalf("NewRootCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("NewRootCAPool returned a nil pool with no error")
	}

	//nolint:staticcheck // Subjects() is deprecated but there's no
	// simpler way to sanity-check a cert count in a *x509.CertPool.
	if got := len(pool.Subjects()); got != 5 {
		t.Errorf("pool has %d certificates, want 5", got)
	}
}

// TestEmbeddedRoots_AreValidSelfSignedCACerts checks each embedded PEM
// individually: it must parse as a real X.509 certificate, be marked as a
// Certificate Authority (able to sign other certificates — which is the
// entire point of a root), and be self-signed (a root has no issuer above
// it). This is the test that would catch "the embedded file is corrupted"
// or "someone pasted in the wrong kind of certificate" mistakes that
// AppendCertsFromPEM's simple true/false success check might not catch on
// its own.
func TestEmbeddedRoots_AreValidSelfSignedCACerts(t *testing.T) {
	roots := map[string][]byte{
		"AmazonRootCA1.pem": amazonRootCA1,
		"AmazonRootCA2.pem": amazonRootCA2,
		"AmazonRootCA3.pem": amazonRootCA3,
		"AmazonRootCA4.pem": amazonRootCA4,
		"GTSRootR4.pem":     gtsRootR4,
	}

	for name, pemBytes := range roots {
		t.Run(name, func(t *testing.T) {
			if len(pemBytes) == 0 {
				t.Fatalf("%s is empty — go:embed may not have picked up the file", name)
			}

			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				t.Fatalf("%s did not parse as a valid PEM certificate", name)
			}

			cert := parseSingleCert(t, pemBytes)
			if !cert.IsCA {
				t.Errorf("%s is not marked as a CA certificate", name)
			}
			if cert.Subject.String() != cert.Issuer.String() {
				t.Errorf("%s is not self-signed: subject=%q issuer=%q", name, cert.Subject, cert.Issuer)
			}
		})
	}
}

func parseSingleCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("no PEM block found")
	}
	if len(rest) != 0 {
		t.Fatalf("expected exactly 1 PEM block, found trailing data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

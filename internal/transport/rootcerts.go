package transport

import (
	"crypto/x509"
	_ "embed"
	"fmt"
)

// The roots embedded below are the explicit trust anchors for every HTTPS
// provider endpoint ZeroDock calls: four Amazon Trust Services roots and the
// Google Trust Services root used by Supabase and Google Cloud APIs. No system trust
// store is consulted.
//
// go:embed compiles these PEM files directly INTO the binary at build
// time — they become part of the program itself, not something read from
// a file at runtime. That's the whole security property we're after: a
// normal HTTP client on Linux trusts whatever certificates happen to be
// sitting in /etc/ssl/certs/ on the machine it's running on, but our
// `scratch` container image (see deploy/Dockerfile) doesn't even HAVE a
// filesystem full of trusted certificates to read — and even if it did,
// trusting "whatever's on disk" means trusting whoever last had write
// access to that disk. By embedding the roots at compile time instead, the
// trust anchors are fixed the moment the binary — and therefore PCR0 — is
// built, and can't be swapped out afterward by modifying files on a
// running system.
//
//go:embed rootcerts/AmazonRootCA1.pem
var amazonRootCA1 []byte

//go:embed rootcerts/AmazonRootCA2.pem
var amazonRootCA2 []byte

//go:embed rootcerts/AmazonRootCA3.pem
var amazonRootCA3 []byte

//go:embed rootcerts/AmazonRootCA4.pem
var amazonRootCA4 []byte

// Google provider endpoints chain through Google Trust Services. This is a
// deliberately embedded root, not a SystemCertPool fallback: the enclave
// trusts the same fixed set of roots even when its scratch image has no OS
// certificate store. Review this pin when Supabase changes its certificate
// chain.
//
//go:embed rootcerts/GTSRootR4.pem
var gtsRootR4 []byte

// GCP control-plane endpoints may chain through GTS Root R1 rather than R4.
// Both are explicit Google-owned trust anchors from pki.goog/repository; this
// remains a pin, never a fallback to the operating system certificate store.
//
//go:embed rootcerts/GTSRootR1.pem
var gtsRootR1 []byte

// NewRootCAPool builds a certificate pool containing ONLY the embedded
// Amazon Trust Services roots above — nothing from the operating system,
// nothing from any file on disk. Passing this pool as an *http.Client's
// TLSClientConfig.RootCAs means that client will refuse to trust ANY
// certificate that doesn't chain up to one of these explicit roots.
func NewRootCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	roots := map[string][]byte{
		"AmazonRootCA1.pem": amazonRootCA1,
		"AmazonRootCA2.pem": amazonRootCA2,
		"AmazonRootCA3.pem": amazonRootCA3,
		"AmazonRootCA4.pem": amazonRootCA4,
		"GTSRootR4.pem":     gtsRootR4,
		"GTSRootR1.pem":     gtsRootR1,
	}
	for name, pemBytes := range roots {
		if !pool.AppendCertsFromPEM(pemBytes) {
			// This should only happen if the embedded .pem file is
			// missing, empty, or corrupted — i.e. a build-time mistake,
			// not something that can happen at runtime from outside
			// input.
			return nil, fmt.Errorf("parse embedded root certificate %s: no valid certificate found", name)
		}
	}

	return pool, nil
}

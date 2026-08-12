// Package verify does what a browser-side or backend verifier has to do
// with an attestation document received from someone else — as opposed to
// package attest, which only knows how to PRODUCE and low-level-decode
// documents, and deliberately has no opinion about whether to trust one.
//
// This is where that opinion lives: decode the document, check its
// signature actually verifies, walk its certificate chain up to a root,
// and decide whether that root is the real AWS Nitro Enclaves root (a
// genuine hardware attestation) or one of MockAttester's throwaway roots
// (a mock one, only acceptable when the caller explicitly allows it).
package verify

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Georgy03/zerodock/internal/attest"
)

// ErrMockNotAllowed is returned when a document verifies successfully —
// valid signature, valid chain — but the chain terminates at a root OTHER
// than the trusted AWS Nitro root (i.e. a mock attestation), and the
// caller did not set Options.AllowMock. Callers can check for this
// specific error (errors.Is) to return a distinct "mock rejected" response
// rather than a generic verification failure.
var ErrMockNotAllowed = errors.New("attestation chains to a mock root, not the trusted AWS Nitro root, and mock attestations are not allowed")

// Options controls policy decisions Verify itself has no fixed opinion
// about.
type Options struct {
	// AllowMock permits attestations that verify successfully but chain
	// to a mock root instead of the real AWS Nitro root. This should be
	// TRUE only in development/staging environments exercising
	// MockAttester, and FALSE in any environment meant to accept real
	// buyer-facing verdicts — a mock attestation proves nothing about
	// real hardware isolation.
	AllowMock bool
}

// Outcome is everything Verify learned about a document that verified
// successfully (or partially — see the Mock field and ErrMockNotAllowed).
type Outcome struct {
	// Mock is true if the chain verified but terminated at a root other
	// than the trusted AWS Nitro root. If Verify returns a nil error,
	// Mock being true means Options.AllowMock was set — this field lets
	// the caller still distinguish and label "verified, but only as a
	// mock" verdicts, e.g. for storage or display.
	Mock bool

	ModuleID  string
	Timestamp time.Time
	UserData  []byte
	Nonce     []byte

	// PCRs are hex-encoded (e.g. "9ab0d3c4..."), not raw bytes — that's
	// the form PCR values are compared and published in (see the
	// "publishable PCR0" convention this whole project has been using),
	// and it's a form that serializes cleanly to JSON/JSONB without the
	// implicit base64-encoding Go's encoding/json gives plain []byte
	// values.
	PCRs map[int]string

	LeafCertificate *x509.Certificate
}

// Verify decodes signedDoc, checks its COSE_Sign1 signature against the
// certificate embedded in the document itself, walks that certificate's
// chain (via the document's CABundle) up to a self-signed root, and
// decides whether that root is trusted.
//
// A note on WHAT "trusted" means here for a chain that terminates at a
// mock root: MockAttester generates a brand new, throwaway root certificate
// every time NewMockAttester is called (see internal/attest/mock.go) — there
// is no single fixed "the mock root" to pin in advance, unlike the real AWS
// Nitro root. So for a mock document, "chain valid" can only mean "the
// certificates inside this document are internally self-consistent" (leaf
// really was signed by the cert that signed it, which really is
// self-signed) — NOT "this is a root we independently already trusted".
// That's exactly why Mock and AllowMock exist: a verified-but-mock outcome
// proves the document wasn't tampered with, but proves NOTHING about
// having run on real, isolated hardware.
func Verify(signedDoc []byte, opts Options) (Outcome, error) {
	doc, err := attest.DecodeDocument(signedDoc)
	if err != nil {
		return Outcome{}, fmt.Errorf("decode document: %w", err)
	}

	leafCert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return Outcome{}, fmt.Errorf("parse leaf certificate: %w", err)
	}

	// Check the signature FIRST, before spending any effort on the
	// certificate chain — there's no point validating a chain attached
	// to a document whose signature doesn't even verify.
	if err := attest.VerifySignature(signedDoc, leafCert.PublicKey); err != nil {
		return Outcome{}, fmt.Errorf("signature: %w", err)
	}

	root, err := verifyChain(leafCert, doc.CABundle, time.UnixMilli(int64(doc.Timestamp)))
	if err != nil {
		return Outcome{}, fmt.Errorf("certificate chain: %w", err)
	}

	outcome := Outcome{
		Mock:            !sameCertificate(root, trustedNitroRoot),
		ModuleID:        doc.ModuleID,
		Timestamp:       time.UnixMilli(int64(doc.Timestamp)).UTC(),
		UserData:        doc.UserData,
		Nonce:           doc.Nonce,
		PCRs:            hexEncodePCRs(doc.PCRs),
		LeafCertificate: leafCert,
	}

	if outcome.Mock && !opts.AllowMock {
		return outcome, ErrMockNotAllowed
	}
	return outcome, nil
}

// verifyChain walks up from leaf through cabundle (the document's
// "Issuing CA bundle", DER-encoded certificates) to a self-signed root,
// using the standard library's own chain verification rather than
// hand-rolled pairwise signature checks — that gets us validity-period
// checking, key usage checking, and correct handling of a multi-certificate
// bundle for free, instead of just re-implementing a weaker subset of it
// ourselves.
//
// checkTime is the time used to evaluate certificate validity windows. We
// deliberately use the document's OWN attested timestamp here, not
// time.Now(): a verdict might be verified long after it was produced
// (that's the whole point of storing it), and MockAttester's certificates
// are only valid for a 25-hour window around when they were minted — using
// wall-clock "now" would make old-but-legitimately-signed documents fail
// verification purely due to the passage of time, which is a different
// problem than "was this document real".
//
// IMPORTANT — WHAT THIS DOES AND DOES NOT PROVE: evaluating the chain at
// the document's own timestamp answers "was this a genuine, correctly
// signed attestation at the moment it claims to have been produced" —
// AUTHENTICITY. It deliberately does NOT answer "is this recent enough to
// still be meaningful" — FRESHNESS. Those are different questions with
// different failure modes: an authentic-but-stale attestation (e.g. a
// two-year-old verdict, still cryptographically perfect) will verify here
// with no error and no warning, because nothing about it is actually
// forged. This function — and Verify above it — will therefore happily
// accept a document that is real but old. If "how old is too old" ever
// matters (e.g. a buyer-facing page deciding whether to show a verdict as
// current), that has to be a SEPARATE, EXPLICIT check with its own
// window, made by whoever is presenting the verdict to a human — not
// smuggled into chain verification here, and not enforced by this API
// at ingest time either. See internal/api's package comment for where
// that responsibility currently sits (nowhere yet — this is a known gap,
// not an oversight).
func verifyChain(leaf *x509.Certificate, cabundleDER [][]byte, checkTime time.Time) (*x509.Certificate, error) {
	if len(cabundleDER) == 0 {
		return nil, fmt.Errorf("document has an empty cabundle")
	}

	var bundle []*x509.Certificate
	for i, der := range cabundleDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse cabundle certificate %d: %w", i, err)
		}
		bundle = append(bundle, cert)
	}

	// A self-signed certificate (subject == issuer, and it verifies its
	// own signature) is the only kind of certificate that's allowed to be
	// a ROOT. Everything else in the bundle is an intermediate. We don't
	// assume a fixed position (AWS's own documentation doesn't guarantee
	// cabundle ordering beyond "root first"), so we scan for it instead
	// of just trusting bundle[0].
	intermediates := x509.NewCertPool()
	var candidateRoots []*x509.Certificate
	for _, cert := range bundle {
		if cert.CheckSignatureFrom(cert) == nil {
			candidateRoots = append(candidateRoots, cert)
		} else {
			intermediates.AddCert(cert)
		}
	}
	if len(candidateRoots) == 0 {
		return nil, fmt.Errorf("no self-signed root certificate found in cabundle")
	}

	for _, root := range candidateRoots {
		roots := x509.NewCertPool()
		roots.AddCert(root)

		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   checkTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err == nil {
			return root, nil
		}
	}

	return nil, fmt.Errorf("leaf certificate does not chain to any self-signed root in the cabundle")
}

// sameCertificate compares two certificates by their raw DER bytes — the
// simplest, least-ambiguous notion of "is this literally the same
// certificate" (as opposed to comparing subjects/fingerprints, which could
// theoretically collide or be spoofed in other fields).
func sameCertificate(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	return string(a.Raw) == string(b.Raw)
}

func hexEncodePCRs(pcrs map[int][]byte) map[int]string {
	out := make(map[int]string, len(pcrs))
	for i, v := range pcrs {
		out[i] = hex.EncodeToString(v)
	}
	return out
}

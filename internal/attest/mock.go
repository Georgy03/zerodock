package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// pcrCount, pcrDigestLen, and the document type this file builds and signs
// are defined in document.go, alongside ExtractTimestamp — see the big
// comment there for why MockAttester's own use of time.Now() below (for
// the document's Timestamp field, and the certificates' validity window)
// is the ONE place in this codebase where calling time.Now() is still
// correct: an attester's whole job is to be a trustworthy source of "what
// time is it", so it can't very well derive that from a document it
// hasn't produced yet.

// --- A quick primer on the cryptography used below ---
//
// To "sign" something digitally, you need a mathematical KEY PAIR: a
// PRIVATE key (kept secret, used to create the signature) and a matching
// PUBLIC key (shared with everyone, used to check/verify a signature).
// Anyone with the public key can confirm "yes, whoever has the matching
// private key signed this" — but they can't create a fake signature
// themselves without the private key.
//
// A CERTIFICATE is a small file that says "here is a public key, and here
// is who it belongs to" — and the certificate itself is signed by someone
// else, to vouch for that claim. If certificate A was signed using the
// private key belonging to certificate B, we say "A was issued BY B", and
// B is A's "issuer". A chain of these (A issued by B, B issued by C, ...)
// is called a CERTIFICATE CHAIN, and the very first one (which signs
// itself, because nobody is "above" it) is called the ROOT.
//
// In a real Nitro Enclave, the root certificate is one that only AWS
// controls — so trusting "AWS's root" is what lets you trust the whole
// chain underneath it. In OUR mock, we generate our OWN throwaway root
// (nobody outside this program trusts it, and it's not meant to be
// trusted) — that's the ONLY thing that's fake here. Everything else
// (the shapes, the algorithms, the signing process) is real.

// MockAttester is our stand-in for a real hardware attester. When it's
// created, it:
//  1. Generates a brand-new "root" key pair and a self-signed root
//     certificate for it (self-signed = it vouches for itself, since
//     there's nothing above a root).
//  2. Generates a second "leaf" key pair, and has the root certificate
//     sign a certificate for it — so leaf is issued BY root.
//  3. Keeps the leaf's PRIVATE key around, ready to sign attestation
//     documents with.
//
// Every call to Attest() then produces a real, valid COSE_Sign1 signature
// using that leaf private key — it's just that our "root of trust" is a
// key we made up ourselves instead of one locked inside real AWS
// hardware.
type MockAttester struct {
	signer    cose.Signer // wraps the leaf private key so the cose library can use it to sign
	leafCert  []byte      // the leaf certificate, DER-encoded (DER is just a standard binary format for certificates)
	rootCert  []byte      // the root certificate, DER-encoded
	publicKey []byte      // the leaf's public key, in a standard binary format (SubjectPublicKeyInfo / "PKIX")
	moduleID  string
	pcrs      map[int][]byte // fixed at construction time; same value on every Attest() call
}

// PCRs returns a copy of the fixed PCR values this attester will embed in
// every attestation document it produces. Tests (and a real verifier
// exercising the mock) can compare against these to confirm the "PCR0
// never changes between calls" property actually holds.
func (m *MockAttester) PCRs() map[int][]byte {
	out := make(map[int][]byte, len(m.pcrs))
	for i, v := range m.pcrs {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[i] = cp
	}
	return out
}

// NewMockAttester builds a fresh root certificate, a fresh leaf
// certificate signed by that root, and a signer ready to produce
// attestation documents. Each call to NewMockAttester makes a brand new,
// independent key pair — nothing is shared between instances.
func NewMockAttester() (*MockAttester, error) {
	// --- Step 1: create the root key pair and root certificate ---

	// P-384 is the specific "elliptic curve" (a particular mathematical
	// recipe) used for the keys — it's the same curve real Nitro
	// Enclaves use, paired with the ES384 signing algorithm below.
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ZeroDock Mock Attestation Root (NOT FOR PRODUCTION)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		// KeyUsage says what this key is allowed to be used for: here,
		// signing other certificates (CertSign) and signing data in
		// general (DigitalSignature).
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		// IsCA + BasicConstraintsValid mark this certificate as a
		// "Certificate Authority" — i.e. one that's allowed to sign
		// OTHER certificates (like our leaf certificate below).
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// CreateCertificate signs "rootTemplate" using rootKey, and (because
	// we pass rootTemplate as BOTH the certificate-to-create and the
	// issuer) it ends up signing itself — a self-signed certificate,
	// exactly what a root needs to be.
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}

	// --- Step 2: create the leaf key pair and leaf certificate ---

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ZeroDock Mock Enclave (NOT FOR PRODUCTION)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// This time we pass rootCert (not leafTemplate) as the issuer, and
	// sign with rootKey (not leafKey) — that's what makes this
	// certificate "issued by root" instead of self-signed.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}

	// Also keep a plain copy of the leaf's public key on its own,
	// separate from the certificate — this mirrors the "public_key"
	// field a real Nitro document includes.
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	// Wrap the leaf's private key in a "Signer" object the cose library
	// knows how to use. ES384 means "ECDSA signatures, using the SHA-384
	// hashing algorithm" — the specific signing recipe Nitro Enclaves
	// use.
	signer, err := cose.NewSigner(cose.AlgorithmES384, leafKey)
	if err != nil {
		return nil, fmt.Errorf("create cose signer: %w", err)
	}

	// Generate the (fake, random) PCR values ONCE here, not per Attest()
	// call — see the big comment on pcrCount/pcrDigestLen above for why
	// that matters.
	pcrs := make(map[int][]byte, pcrCount)
	for i := 0; i < pcrCount; i++ {
		digest := make([]byte, pcrDigestLen)
		if _, err := rand.Read(digest); err != nil {
			return nil, fmt.Errorf("generate mock pcr%d: %w", i, err)
		}
		pcrs[i] = digest
	}

	return &MockAttester{
		signer:    signer,
		leafCert:  leafDER,
		rootCert:  rootDER,
		publicKey: publicKeyDER,
		moduleID:  "zerodock-mock-0000000000000000",
		pcrs:      pcrs,
	}, nil
}

// Attest builds one attestation document containing userData and nonce,
// and signs it. The PCRs, certificate, and key are always the same
// (they're fixed to this MockAttester instance); only the timestamp and
// the caller-supplied nonce and userData change between calls.
//
// nonce must be supplied by the CALLER, not generated in here — see the
// comment on the Attester interface for why that matters for replay
// protection.
func (m *MockAttester) Attest(userData, nonce []byte) ([]byte, error) {
	doc := Document{
		ModuleID:    m.moduleID,
		Digest:      "SHA384",
		Timestamp:   uint64(time.Now().UnixMilli()),
		PCRs:        m.pcrs,
		Certificate: m.leafCert,
		CABundle:    [][]byte{m.rootCert},
		PublicKey:   m.publicKey,
		UserData:    userData,
		Nonce:       nonce,
	}

	// CBOR ("Concise Binary Object Representation") is a compact binary
	// format, similar in spirit to JSON but smaller and faster to parse
	// — it's the standard format COSE documents use to encode their
	// contents. cbor.Marshal turns our Go `document` struct into its
	// CBOR byte representation.
	payload, err := cbor.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation document: %w", err)
	}

	// COSE_Sign1 is a standard (RFC 8152) way of wrapping a payload
	// together with a digital signature over it, all in one CBOR
	// structure. cose.Sign1 does the actual signing: it takes our CBOR
	// payload, signs it with the leaf private key (via m.signer), and
	// returns the finished, signed document as bytes. (The algorithm
	// used — ES384 — gets recorded automatically inside the signed
	// document by this call, because we created m.signer with that
	// algorithm above.)
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{},
	}
	signed, err := cose.Sign1(rand.Reader, m.signer, headers, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("sign attestation document: %w", err)
	}

	// cose.Sign1 emits the canonical, CBOR-tag-18 COSE_Sign1 encoding. Keep
	// this tagged form: it is the byte-level wire shape a verifier should learn
	// from the mock, even though ExtractTimestamp also accepts older untagged
	// AWS NSM documents for backwards compatibility.
	return signed, nil
}

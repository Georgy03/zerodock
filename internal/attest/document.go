package attest

import (
	"crypto"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// pcrCount and pcrDigestLen describe the shape of "PCRs" in the attestation
// document. A PCR ("Platform Configuration Register") is a small piece of
// data that, on a real Nitro Enclave, records a fingerprint of exactly
// what code and settings the enclave booted with — kind of like a
// tamper-evident checksum of the running program itself. Real Nitro
// enclaves report PCR0, PCR1, and PCR2, and each one is a 48-byte number
// (because it's a SHA-384 hash — SHA-384 hashes are always exactly 48
// bytes long).
//
// Critically, a real PCR0 is CONSTANT for a given enclave image — that's
// the whole point of it. A buyer publishes "our scanner's PCR0 is X", and
// every attestation your enclave produces should report that same X
// forever (until you actually change and rebuild the scanner). If PCR0
// changed on every attestation, nobody could ever check "is this really
// running ZeroDock's unmodified code?" — there'd be nothing fixed to
// compare against. So MockAttester generates its (fake, random) PCR values
// ONCE, at construction, and reuses them on every Attest() call — never
// fresh random values per call.
const (
	pcrCount     = 3
	pcrDigestLen = 48
)

// Document is the actual content that gets signed and sealed, for BOTH
// MockAttester and NSMAttester — that's why it's exported and lives here
// rather than inside mock.go, where it started: DecodeDocument below is
// meant to be called by code OUTSIDE this package too (the week-5 backend
// verifies submitted attestations server-side, in internal/verify). Its
// field names and structure are copied EXACTLY from what a real AWS Nitro
// Enclave attestation document looks like
// (https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html).
// That's the whole point of the mock: a verifier built against
// MockAttester's output should be able to point at a REAL attestation
// document with no code changes, other than trusting a different root
// certificate — see internal/verify for exactly that split.
//
// Field-by-field, in plain English:
//   - ModuleID: a name identifying which enclave produced this document.
//   - Digest: which hashing algorithm was used for the PCRs (we always
//     use "SHA384").
//   - Timestamp: when this document was created (in milliseconds since
//     January 1, 1970 — a common way computers represent "now"). For a
//     REAL Nitro Enclave, this comes from the Nitro hypervisor's own
//     clock, not the enclave guest OS's clock — which matters, because an
//     enclave has no reliable clock of its own until it has network access
//     for something like NTP. See ExtractTimestamp below.
//   - PCRs: the boot/code fingerprints described above.
//   - Certificate: proves WHO signed this document (see below).
//   - CABundle: the "chain of trust" that proves the certificate itself
//     is legitimate (see below).
//   - PublicKey: an extra copy of the signer's public key.
//   - UserData: whatever data the caller asked us to seal — in
//     ZeroDock's case, this will be a fingerprint (hash) of the scan
//     results.
//   - Nonce: a random number included purely so that two attestations
//     covering the exact same UserData still come out looking different
//     from each other, which helps prove "this is a fresh document, not
//     an old one being replayed".
type Document struct {
	ModuleID    string         `cbor:"module_id"`
	Digest      string         `cbor:"digest"`
	Timestamp   uint64         `cbor:"timestamp"`
	PCRs        map[int][]byte `cbor:"pcrs"`
	Certificate []byte         `cbor:"certificate"`
	CABundle    [][]byte       `cbor:"cabundle"`
	PublicKey   []byte         `cbor:"public_key"`
	UserData    []byte         `cbor:"user_data"`
	Nonce       []byte         `cbor:"nonce"`
}

// DecodeDocument decodes a signed attestation document's PAYLOAD into a
// Document — WITHOUT checking the signature over it. Reading the fields
// out is a separate step from deciding whether to trust them, on purpose:
// you need the certificate INSIDE the document (Document.Certificate)
// before you even know which public key VerifySignature should check the
// signature against. See internal/verify for the full "decode, then
// decide whether to trust" flow a real verifier needs.
func DecodeDocument(signedDoc []byte) (Document, error) {
	msg, err := parseCOSESign1(signedDoc)
	if err != nil {
		return Document{}, err
	}

	var doc Document
	if err := cbor.Unmarshal(msg.Payload, &doc); err != nil {
		return Document{}, fmt.Errorf("decode attestation document payload: %w", err)
	}
	return doc, nil
}

// ExtractTimestamp pulls just the Timestamp field out of a signed
// attestation document (the same bytes Attest returns), without verifying
// the signature.
//
// WHY THIS EXISTS: an enclave has no battery-backed real-time clock and no
// network access until vsock is fully wired up for it — so its guest OS's
// notion of "what time is it" cannot be trusted (it may start at the Unix
// epoch, or wherever it happened to be left, with nothing to correct it).
// The Nitro hypervisor's clock, on the other hand, IS reliable — it's
// backed by the physical host, not the enclave guest. Every attestation
// document's Timestamp field is stamped using that hypervisor clock (for
// NSMAttester) or the local system clock (for MockAttester, which has no
// hypervisor to ask and is only used outside an enclave anyway, where the
// system clock is trustworthy). So instead of calling time.Now() anywhere
// that the RESULT affects what ends up in the scan report, callers get one
// attestation document early, extract ITS timestamp with this function,
// and use that as "now" for the rest of the run.
//
// WHY NO SIGNATURE VERIFICATION HERE: this function is meant to be called
// on a document THIS PROGRAM JUST PRODUCED, by calling its own attester —
// not on a document received from someone else. We already trust whatever
// we just asked the attester to build; we're not re-deriving trust in it,
// just reading a field back out of it. A downstream verifier checking a
// document from a THIRD party still MUST verify the signature (and PCRs,
// and cert chain) before trusting anything in it, timestamp included —
// see internal/verify for that.
func ExtractTimestamp(signedDoc []byte) (time.Time, error) {
	doc, err := DecodeDocument(signedDoc)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(int64(doc.Timestamp)).UTC(), nil
}

// VerifySignature checks that signedDoc's COSE_Sign1 signature is
// cryptographically valid under pub. It does NOT decide whether pub
// itself should be trusted — that's a policy question (which root
// certificate do we trust, mock or real AWS Nitro?) that belongs to the
// caller, not to this low-level signing/parsing package. Callers get pub
// by decoding the document (DecodeDocument), parsing its Certificate
// field as an X.509 certificate, and pulling out that certificate's
// public key — see internal/verify.
func VerifySignature(signedDoc []byte, pub crypto.PublicKey) error {
	msg, err := parseCOSESign1(signedDoc)
	if err != nil {
		return err
	}

	verifier, err := cose.NewVerifier(cose.AlgorithmES384, pub)
	if err != nil {
		return fmt.Errorf("build verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("signature does not verify: %w", err)
	}
	return nil
}

// parseCOSESign1 decodes signedDoc as a COSE_Sign1 message, accepting
// either of the two encodings encountered in practice. The canonical COSE
// representation wraps the four-element Sign1 array in CBOR tag 18;
// go-cose's Sign1Message handles that form. AWS Nitro NSM documents
// observed in the field use the same four-element Sign1 array without the
// outer tag, so we accept that untagged representation too. Both forms
// carry identical payload and signature semantics; only the outer CBOR
// wrapper differs.
//
// Keep the tagged attempt first. It is the form MockAttester deliberately
// emits and the format a new verifier should produce. The untagged
// fallback preserves compatibility with real NSM documents already issued
// by Nitro.
func parseCOSESign1(signedDoc []byte) (*cose.Sign1Message, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(signedDoc); err == nil {
		return &msg, nil
	} else {
		taggedErr := err

		var untagged cose.UntaggedSign1Message
		if err := untagged.UnmarshalCBOR(signedDoc); err == nil {
			converted := cose.Sign1Message(untagged)
			return &converted, nil
		} else {
			return nil, fmt.Errorf("decode COSE_Sign1 envelope (tagged: %v; untagged: %v)", taggedErr, err)
		}
	}
}

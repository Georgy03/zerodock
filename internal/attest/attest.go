// Package attest is about PROVING that a scan report is genuine and
// untampered — that's what "attestation" means here. Imagine getting a
// sealed envelope with a wax stamp on it: you can't be 100% sure what's
// inside just by looking at the outside, but the seal proves nobody has
// opened and swapped the contents since it was sealed.
//
// MockAttester provides a local development implementation, while
// NSMAttester delegates signing to the Nitro Security Module available at
// /dev/nsm inside an AWS Nitro Enclave.
package attest

// Attester is the "contract" that any attestation implementation must
// follow: give it some data (userData) plus a nonce, and it hands back a
// signed document proving "this exact data was sealed by me, right after
// you asked".
//
// Because this is an interface (a description of WHAT something does,
// not HOW), the rest of ZeroDock can work with "any Attester" without
// caring whether it's the mock version or a real hardware-backed one.
type Attester interface {
	// Attest takes some bytes (in our case, a hash/fingerprint of the
	// scan results) and a nonce, and returns a signed attestation
	// document — specifically, one encoded in a standard format called
	// COSE_Sign1, which is the same format real AWS Nitro Enclaves use.
	// userData and nonce both end up embedded inside that document, in
	// its "user_data" and "nonce" fields.
	//
	// The CALLER must generate nonce (a random value, different every
	// time), not the attester itself. This is what makes the resulting
	// document proof of a FRESH attestation instead of an old one being
	// replayed: only whoever asked for this specific attestation knows
	// what nonce they picked, so a signed document echoing that same
	// nonce back proves it was created in response to THIS request, not
	// reused from an earlier one.
	Attest(userData, nonce []byte) ([]byte, error)
}

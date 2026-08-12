//go:build !linux

// This file is the mirror image of nsm.go's build tag: it compiles on
// every OS EXCEPT Linux. Without it, `go build` would simply fail on a
// Mac or Windows dev machine, because nsm.go references Linux-only
// syscalls. Instead, this file provides the exact same NSMAttester type
// and NewNSMAttester function, but every call immediately returns a clear
// error explaining why — so the rest of the program (cmd/scanner, tests,
// etc.) can be built and read on any machine, even though NSMAttester can
// only ever actually WORK inside a real Nitro Enclave.
package attest

import "errors"

// errUnsupportedPlatform is returned by every method below. It exists as
// a single value so all the error messages stay word-for-word identical.
var errUnsupportedPlatform = errors.New("NSM attestation is only available inside an AWS Nitro Enclave (Linux); this binary was built for a different platform")

// NSMAttester mirrors the real, Linux-only NSMAttester's shape so code
// that references the type still compiles on other platforms. It can
// never actually be constructed successfully here — see
// errUnsupportedPlatform.
type NSMAttester struct{}

var _ Attester = (*NSMAttester)(nil)

// NewNSMAttester always fails on non-Linux platforms.
func NewNSMAttester() (*NSMAttester, error) {
	return nil, errUnsupportedPlatform
}

// Attest always fails on non-Linux platforms. It exists so *NSMAttester
// still satisfies the Attester interface here, the same as it does on
// Linux.
func (a *NSMAttester) Attest(userData, nonce []byte) ([]byte, error) {
	return nil, errUnsupportedPlatform
}

// Close always fails on non-Linux platforms, matching the real
// NSMAttester's Close method.
func (a *NSMAttester) Close() error {
	return errUnsupportedPlatform
}

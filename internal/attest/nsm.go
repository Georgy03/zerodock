//go:build linux

// This file only compiles on Linux, because /dev/nsm — the actual hardware
// device this code talks to — only exists inside an AWS Nitro Enclave,
// which always runs Linux. See nsm_unsupported.go for what happens if you
// try to build this package on any other OS (e.g. developing on a Mac).
package attest

import (
	"fmt"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type nsmSession interface {
	Send(request.Request) (response.Response, error)
	Close() error
}

// NSMAttester is the REAL attester: instead of generating its own pretend
// key and certificate like MockAttester does, it asks the Nitro Security
// Module (NSM) — a piece of hardware built into the enclave's virtual
// machine — to produce and sign the attestation document itself, using a
// key that only AWS's hardware knows and that this program never sees.
// That's what makes it trustworthy: even ZeroDock's own code can't forge a
// document, because it never has access to the signing key at all.
type NSMAttester struct {
	session nsmSession
}

var _ Attester = (*NSMAttester)(nil)

// NewNSMAttester opens a session with /dev/nsm, the special device file
// through which an enclave talks to its NSM. This will fail with an error
// (rather than hang or crash) if run anywhere that isn't inside a real
// Nitro Enclave — e.g. a normal EC2 instance or your laptop — because that
// device file simply won't exist there.
func NewNSMAttester() (*NSMAttester, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("open /dev/nsm session: %w", err)
	}
	return &NSMAttester{session: session}, nil
}

// Close releases the /dev/nsm session. Call this when you're done making
// attestations (e.g. right before the enclave process exits).
func (a *NSMAttester) Close() error {
	return a.session.Close()
}

// Attest asks the NSM hardware to build and sign a real attestation
// document. Unlike MockAttester, there is no CBOR-building or COSE-signing
// code here at all — that's the whole point. We just hand the NSM our
// userData and nonce, and it hands back the finished, already-signed
// COSE_Sign1 document. The NSM itself fills in the real PCR values (actual
// measurements of the enclave image that's running), a certificate signed
// by AWS's own Nitro certificate chain, and everything else.
func (a *NSMAttester) Attest(userData, nonce []byte) ([]byte, error) {
	req := &request.Attestation{
		UserData: userData,
		Nonce:    nonce,
		// PublicKey is left empty on purpose: it's only used when you
		// want the NSM to also encrypt a secret back to you using that
		// key (a separate feature from attestation itself). We don't
		// need that here — we only want the signed document back.
	}

	res, err := a.session.Send(req)
	if err != nil {
		return nil, fmt.Errorf("send attestation request to NSM: %w", err)
	}

	if res.Error != "" {
		return nil, fmt.Errorf("NSM returned an error: %s", res.Error)
	}
	if res.Attestation == nil || len(res.Attestation.Document) == 0 {
		return nil, fmt.Errorf("NSM response did not include an attestation document")
	}

	// res.Attestation.Document is already the raw, complete COSE_Sign1
	// bytes — exactly the same shape MockAttester.Attest returns, just
	// produced by real hardware instead of a throwaway in-process key.
	return res.Attestation.Document, nil
}

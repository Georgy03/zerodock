//go:build linux

package attest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

type fakeNSMSession struct {
	request request.Request
	result  response.Response
	err     error
}

func (s *fakeNSMSession) Send(req request.Request) (response.Response, error) {
	s.request = req
	return s.result, s.err
}

func (s *fakeNSMSession) Close() error { return nil }

func TestNSMAttesterAttest(t *testing.T) {
	wantDocument := []byte{0xd2, 0x84, 0x43, 0xa1}
	session := &fakeNSMSession{result: response.Response{
		Attestation: &response.Attestation{Document: wantDocument},
	}}
	attester := &NSMAttester{session: session}

	userData := []byte("results hash")
	nonce := []byte("fresh nonce")
	gotDocument, err := attester.Attest(userData, nonce)
	if err != nil {
		t.Fatalf("Attest() error = %v", err)
	}
	if !bytes.Equal(gotDocument, wantDocument) {
		t.Fatalf("Attest() document = %x, want %x", gotDocument, wantDocument)
	}

	gotRequest, ok := session.request.(*request.Attestation)
	if !ok {
		t.Fatalf("Send() request type = %T, want *request.Attestation", session.request)
	}
	if !bytes.Equal(gotRequest.UserData, userData) {
		t.Errorf("request user data = %x, want %x", gotRequest.UserData, userData)
	}
	if !bytes.Equal(gotRequest.Nonce, nonce) {
		t.Errorf("request nonce = %x, want %x", gotRequest.Nonce, nonce)
	}
}

// TestAttestersProduceDocumentsExtractTimestampAccepts makes the mock and the
// NSM adapter meet at the same parser boundary. The mock emits canonical
// tagged COSE_Sign1; the fake NSM returns the untagged NSM-compatible form.
// In production the latter bytes come directly from /dev/nsm.
func TestAttestersProduceDocumentsExtractTimestampAccepts(t *testing.T) {
	mock, err := NewMockAttester()
	if err != nil {
		t.Fatalf("NewMockAttester: %v", err)
	}
	tagged, err := mock.Attest([]byte("time-sync"), []byte("nonce"))
	if err != nil {
		t.Fatalf("mock Attest: %v", err)
	}
	if len(tagged) < 2 || tagged[0] != 0xd2 {
		t.Fatalf("mock document starts %x, want tagged COSE_Sign1", tagged)
	}

	nsmAttester := &NSMAttester{session: &fakeNSMSession{result: response.Response{
		Attestation: &response.Attestation{Document: tagged[1:]},
	}}}
	nsmDoc, err := nsmAttester.Attest([]byte("time-sync"), []byte("nonce"))
	if err != nil {
		t.Fatalf("NSMAttester.Attest: %v", err)
	}

	for _, tc := range []struct {
		name string
		doc  []byte
	}{
		{name: "mock tagged", doc: tagged},
		{name: "NSM untagged", doc: nsmDoc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ExtractTimestamp(tc.doc); err != nil {
				t.Fatalf("ExtractTimestamp: %v", err)
			}
		})
	}
}

func TestNSMAttesterAttestErrors(t *testing.T) {
	tests := []struct {
		name    string
		session *fakeNSMSession
	}{
		{
			name:    "send",
			session: &fakeNSMSession{err: errors.New("ioctl failed")},
		},
		{
			name: "NSM response",
			session: &fakeNSMSession{result: response.Response{
				Error: response.ErrorCode("InvalidArgument"),
			}},
		},
		{
			name:    "missing document",
			session: &fakeNSMSession{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attester := &NSMAttester{session: tt.session}
			if _, err := attester.Attest(nil, nil); err == nil {
				t.Fatal("Attest() error = nil, want non-nil")
			}
		})
	}
}

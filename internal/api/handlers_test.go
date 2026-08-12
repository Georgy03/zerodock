package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/report"
	"github.com/Georgy03/zerodock/internal/verify"
)

// newTestServer builds a Server around a fakeStore, with verifyFn stubbed
// to return outcome/err regardless of input — real signature/chain
// verification is internal/verify's own responsibility and already has
// its own tests; these tests are about whether the HANDLERS react
// correctly to a given verification outcome.
func newTestServer(fs *fakeStore, outcome verify.Outcome, verifyErr error) *Server {
	return &Server{
		store:      fs,
		verifyOpts: verify.Options{AllowMock: true},
		publicBase: "https://verify.example",
		verifyFn: func(_ []byte, _ verify.Options) (verify.Outcome, error) {
			return outcome, verifyErr
		},
	}
}

// validSubmission builds a report.Report whose ResultsHash and
// Attestation are internally consistent with each other and with the
// outcome a stubbed verifyFn will return — i.e. exactly what a real
// scanner+attester would have produced. Individual tests mutate the
// result to break one specific thing.
func validSubmission(t *testing.T) (report.Report, verify.Outcome) {
	t.Helper()

	content := report.AttestedContent{
		ScannerVersion:   "v1.2.3",
		AccountID:        "123456789012",
		ScopeVerified:    true,
		TimeVerified:     true,
		RequestedRegions: []string{"us-east-1"},
		ScannedRegions:   []string{"us-east-1"},
		Checks: map[string]report.CheckOutput{
			"aws.ebs.encryption": {
				Title: "Unencrypted EBS volumes",
				Tier:  checks.ProviderAttested,
				Result: checks.Result{
					Status: checks.StatusPass,
					Count:  2,
				},
			},
		},
	}
	hash := hashAttestedContent(content)
	userData, err := hex.DecodeString(hash)
	if err != nil {
		t.Fatalf("decode test hash: %v", err)
	}

	sub := report.Report{
		ScanID:          "scan-1",
		Timestamp:       time.Now().UTC(),
		AttestedContent: content,
		ResultsHash:     hash,
		Attestation: &report.AttestationOutput{
			Format: "COSE_Sign1/ES384 (mock attester)",
			Doc:    base64.StdEncoding.EncodeToString([]byte("pretend-cose-bytes")),
		},
	}

	outcome := verify.Outcome{
		Mock:     true,
		ModuleID: "zerodock-mock-test",
		UserData: userData,
		PCRs:     map[int]string{0: "aa", 1: "bb", 2: "cc"},
	}
	return sub, outcome
}

func postVerdict(t *testing.T, s *Server, sub report.Report) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal submission: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/verdicts", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	return rec
}

func TestHandleCreateVerdict_Success(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["scan_id"] != sub.ScanID {
		t.Errorf("scan_id = %v, want %v", resp["scan_id"], sub.ScanID)
	}
	if resp["share_url"] != "https://verify.example/v1/share/token-123456789012" {
		t.Errorf("share_url = %v", resp["share_url"])
	}
	if len(fs.verdictsByToken) != 1 {
		t.Errorf("expected exactly one verdict persisted, got %d subjects", len(fs.verdictsByToken))
	}
}

func TestHandleCreateVerdict_TamperedResultsHashRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	sub.Checks["aws.ebs.encryption"] = report.CheckOutput{
		Title: "tampered after hashing",
		Tier:  checks.ProviderAttested,
		Result: checks.Result{
			Status: checks.StatusPass,
		},
	}
	// ResultsHash is left as the ORIGINAL hash — now stale relative to
	// the mutated Checks map above.

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if len(fs.verdictsByToken) != 0 {
		t.Error("tampered submission must not be persisted")
	}
}

func TestHandleCreateVerdict_TamperedScannerVersionRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	// The hash and sealed user_data still describe v1.2.3. An API client
	// cannot retarget the browser to another release manifest after signing.
	sub.ScannerVersion = "v9.9.9"

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)
	rec := postVerdict(t, s, sub)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if len(fs.verdictsByToken) != 0 {
		t.Error("submission with a substituted scanner_version must not be persisted")
	}
}

func TestHandleCreateVerdict_UserDataMismatchRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	// The attestation's sealed user_data does NOT match sub.ResultsHash —
	// simulating a genuinely-signed attestation from a DIFFERENT scan
	// attached to these results.
	outcome.UserData = []byte("not-the-right-hash-bytes")

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if len(fs.verdictsByToken) != 0 {
		t.Error("mismatched user_data submission must not be persisted")
	}
}

func TestHandleCreateVerdict_MockNotAllowedRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, verify.ErrMockNotAllowed)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestHandleCreateVerdict_DuplicateScanIDRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	first := postVerdict(t, s, sub)
	if first.Code != http.StatusCreated {
		t.Fatalf("first submission status = %d, want %d", first.Code, http.StatusCreated)
	}

	second := postVerdict(t, s, sub)
	if second.Code != http.StatusConflict {
		t.Fatalf("second submission status = %d, want %d; body = %s", second.Code, http.StatusConflict, second.Body.String())
	}
}

// TestHandleCreateVerdict_ScopeUnverifiedRejected confirms a report that
// admits it couldn't confirm which account it scanned is refused outright
// — before any cryptographic check even runs — rather than being stored
// as if it were ordinary evidence.
func TestHandleCreateVerdict_ScopeUnverifiedRejected(t *testing.T) {
	sub, outcome := validSubmission(t)
	sub.ScopeVerified = false
	// Recompute the hash to match the mutated content, so this test is
	// specifically about the ScopeVerified check, not a hash mismatch.
	sub.ResultsHash = hashAttestedContent(sub.AttestedContent)
	hashBytes, err := hex.DecodeString(sub.ResultsHash)
	if err != nil {
		t.Fatalf("decode test hash: %v", err)
	}
	outcome.UserData = hashBytes

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if len(fs.verdictsByToken) != 0 {
		t.Error("a submission with scope_verified=false must not be persisted")
	}
}

func TestHandleCreateVerdict_MissingRequiredField(t *testing.T) {
	sub, outcome := validSubmission(t)
	sub.ScanID = ""

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateVerdict_MissingScannerVersion(t *testing.T) {
	sub, outcome := validSubmission(t)
	sub.ScannerVersion = ""

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)
	rec := postVerdict(t, s, sub)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("scanner_version")) {
		t.Fatalf("body does not identify scanner_version: %s", rec.Body.String())
	}
}

func TestHandleCreateVerdict_InvalidBase64Attestation(t *testing.T) {
	sub, outcome := validSubmission(t)
	sub.Attestation.Doc = "not valid base64!!!"

	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	rec := postVerdict(t, s, sub)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleLatest_UnknownTokenIs404(t *testing.T) {
	fs := newFakeStore()
	s := newTestServer(fs, verify.Outcome{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/share/does-not-exist", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleLatest_KnownTokenNoVerdictsIs404(t *testing.T) {
	fs := newFakeStore()
	fs.addSubjectOnly("999999999999", "token-999999999999")
	s := newTestServer(fs, verify.Outcome{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/share/token-999999999999", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleLatest_ReturnsMostRecentlyAttested(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	if rec := postVerdict(t, s, sub); rec.Code != http.StatusCreated {
		t.Fatalf("setup: first post status = %d", rec.Code)
	}

	sub2 := sub
	sub2.ScanID = "scan-2"
	sub2.Timestamp = sub.Timestamp.Add(time.Hour)
	if rec := postVerdict(t, s, sub2); rec.Code != http.StatusCreated {
		t.Fatalf("setup: second post status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/share/token-123456789012", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var view verdictView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if view.ScanID != "scan-2" {
		t.Errorf("scan_id = %q, want %q (the later-attested one)", view.ScanID, "scan-2")
	}
	if view.ScannerVersion != sub.ScannerVersion {
		t.Errorf("scanner_version = %q, want %q", view.ScannerVersion, sub.ScannerVersion)
	}
}

func TestHandleHistory_ReturnsAllVerdictsForToken(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	postVerdict(t, s, sub)
	sub2 := sub
	sub2.ScanID = "scan-2"
	postVerdict(t, s, sub2)

	req := httptest.NewRequest(http.MethodGet, "/v1/share/token-123456789012/history", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp struct {
		Token    string        `json:"token"`
		Verdicts []verdictView `json:"verdicts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Verdicts) != 2 {
		t.Fatalf("got %d verdicts, want 2", len(resp.Verdicts))
	}
}

func TestHandleHistory_UnknownTokenIs404(t *testing.T) {
	fs := newFakeStore()
	s := newTestServer(fs, verify.Outcome{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/share/does-not-exist/history", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestHandleLatest_RevokedTokenIs410 confirms a revoked share link
// returns 410 Gone — distinct from 404, because the token DID work once
// and was deliberately killed, which a buyer with a bookmarked link
// deserves to be told rather than being left to guess "was this ever
// real?".
func TestHandleLatest_RevokedTokenIs410(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	if rec := postVerdict(t, s, sub); rec.Code != http.StatusCreated {
		t.Fatalf("setup: post status = %d, body = %s", rec.Code, rec.Body.String())
	}
	fs.revokeToken("token-123456789012")

	req := httptest.NewRequest(http.MethodGet, "/v1/share/token-123456789012", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusGone, rec.Body.String())
	}
}

// TestHandleHistory_RevokedTokenIs410 is the same check against
// /history — revocation has to block BOTH read paths, not just the
// "latest" one.
func TestHandleHistory_RevokedTokenIs410(t *testing.T) {
	sub, outcome := validSubmission(t)
	fs := newFakeStore()
	s := newTestServer(fs, outcome, nil)

	if rec := postVerdict(t, s, sub); rec.Code != http.StatusCreated {
		t.Fatalf("setup: post status = %d, body = %s", rec.Code, rec.Body.String())
	}
	fs.revokeToken("token-123456789012")

	req := httptest.NewRequest(http.MethodGet, "/v1/share/token-123456789012/history", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusGone, rec.Body.String())
	}
}

// TestHandleLatest_StoreFailureIs500 confirms a database problem surfaces
// as a 500, not a 404 or a crash — ShareLinkStatus failing is a different
// condition than "the token doesn't exist", and callers (and monitoring)
// need to be able to tell the two apart.
func TestHandleLatest_StoreFailureIs500(t *testing.T) {
	fs := newFakeStore()
	fs.forceErr = errFakeStoreForced
	s := newTestServer(fs, verify.Outcome{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/share/whatever", nil)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

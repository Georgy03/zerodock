package api

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/questionnaire"
	"github.com/Georgy03/zerodock/internal/report"
	"github.com/Georgy03/zerodock/internal/store"
	"github.com/Georgy03/zerodock/internal/verify"
)

const maxQuestionnaireUploadBytes = 16 << 20 // 16 MiB

// handleCreateVerdict implements POST /v1/verdicts. A submission is
// accepted only if ALL of the following hold — any failure is a 4xx, and
// NOTHING gets persisted:
//
//  1. The body decodes as a report.Report (the same shape cmd/scanner
//     prints).
//  2. Re-marshaling the submitted AttestedContent produces the SAME
//     SHA-384 the submission itself claims as results_sha384 — i.e. the
//     submitted checks/scope/time/regions weren't altered after the
//     scanner computed that hash.
//  3. The attached attestation document's signature verifies, and its
//     certificate chain leads to a trusted root (the real AWS Nitro
//     root, or — only if this server was started with AllowMock — a
//     mock root).
//  4. The attestation's OWN sealed user_data matches results_sha384 too
//     — this is what actually ties the SIGNED, hardware-attested
//     document to THESE SPECIFIC results. Without this check, a
//     genuinely-signed attestation from a totally different scan could
//     be attached to fabricated results and steps 1-3 would still all
//     pass.
//
// Also rejected, before any of the above: sub.ScopeVerified == false. If
// the scanner itself couldn't confirm which AWS account it was looking
// at (see report.AttestedContent.ScopeVerified's own doc comment), no
// amount of cryptographic verification of THIS document changes that —
// a report that can't say what it scanned isn't evidence, and shouldn't
// enter the append-only ledger at all. Note this is a DIFFERENT kind of
// rejection from the freshness gap described in this package's doc
// comment: scope is something the scanner itself already knows it
// couldn't establish, not a judgment call about the passage of time.
func (s *Server) handleCreateVerdict(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var sub report.Report
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if missing := requiredFieldsMissing(sub); missing != "" {
		writeError(w, http.StatusBadRequest, "missing required field: "+missing)
		return
	}

	if !sub.ScopeVerified {
		writeError(w, http.StatusUnprocessableEntity, "scope_verified is false — a report that cannot confirm which account it scanned cannot be stored as evidence")
		return
	}
	if scopeErr := validateOrganizationScope(sub.AttestedContent); scopeErr != "" {
		writeError(w, http.StatusUnprocessableEntity, scopeErr)
		return
	}

	docBytes, err := base64.StdEncoding.DecodeString(sub.Attestation.Doc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "attestation.cose_sign1_base64 is not valid base64: "+err.Error())
		return
	}

	// Step 2: does the submitted content hash to what it claims?
	recomputedHash := hashAttestedContent(sub.AttestedContent)
	if recomputedHash != sub.ResultsHash {
		writeError(w, http.StatusUnprocessableEntity, "results_sha384 does not match a fresh hash of the submitted content")
		return
	}

	// Step 3: does the attestation itself verify, against a trusted root?
	outcome, err := s.verifyFn(docBytes, s.verifyOpts)
	if err != nil {
		if errors.Is(err, verify.ErrMockNotAllowed) {
			writeError(w, http.StatusUnprocessableEntity, "attestation verified but chains to a mock root, and mock attestations are not accepted by this server")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "attestation verification failed: "+err.Error())
		return
	}

	// Step 4: does the SIGNED document's own user_data match too?
	if hex.EncodeToString(outcome.UserData) != sub.ResultsHash {
		writeError(w, http.StatusUnprocessableEntity, "attestation user_data does not match results_sha384 — this attestation was not sealed over these results")
		return
	}

	checksJSON, err := json.Marshal(sub.Checks)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error encoding checks")
		return
	}
	pcrsJSON, err := json.Marshal(outcome.PCRs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error encoding PCRs")
		return
	}

	v, err := s.store.CreateVerdict(r.Context(), store.NewVerdict{
		ScannerVersion:         sub.ScannerVersion,
		OrganizationVerified:   sub.OrganizationVerified,
		OrgID:                  emptyToNil(sub.OrgID),
		NoOrganization:         sub.NoOrganization,
		OrganizationWarning:    emptyToNil(sub.OrganizationWarning),
		AccountsListed:         sub.AccountsListed,
		AccountsScanned:        sub.AccountsScanned,
		SupabaseOrganizationID: emptyToNil(sub.SupabaseOrganizationID),
		ProjectsListed:         sub.ProjectsListed,
		ProjectsScanned:        sub.ProjectsScanned,
		ScanID:                 sub.ScanID,
		AccountID:              sub.AccountID,
		AttestedAt:             sub.Timestamp,
		ScopeVerified:          sub.ScopeVerified,
		ScopeWarning:           emptyToNil(sub.ScopeWarning),
		TimeVerified:           sub.TimeVerified,
		TimeWarning:            emptyToNil(sub.TimeWarning),
		RequestedRegions:       sub.RequestedRegions,
		ScannedRegions:         sub.ScannedRegions,
		RegionsWarning:         emptyToNil(sub.RegionsWarning),
		ResultsSHA384:          sub.ResultsHash,
		Checks:                 checksJSON,
		AttestationFormat:      sub.Attestation.Format,
		AttestationMock:        outcome.Mock,
		PCRs:                   pcrsJSON,
		AttestationRaw:         docBytes,
	})
	if err != nil {
		if errors.Is(err, store.ErrDuplicateScan) {
			writeError(w, http.StatusConflict, "a verdict for this scan_id already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to persist verdict")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"verdict_id": v.ID,
		"scan_id":    v.ScanID,
		"token":      v.ShareToken,
		"share_url":  s.shareURL(v.ShareToken),
		"mock":       outcome.Mock,
	})
}

func validateOrganizationScope(content report.AttestedContent) string {
	if len(content.AccountsScanned) == 0 {
		return "accounts_scanned is empty — a report must identify every account it actually scanned"
	}
	if !content.OrganizationVerified {
		if content.OrganizationWarning == "" {
			return "organization enumeration is unverified but organization_warning is empty"
		}
		return ""
	}
	if len(content.AccountsListed) == 0 {
		return "organization_verified is true but accounts_listed is empty"
	}
	if content.NoOrganization {
		if content.OrgID != "" {
			return "no_organization is true but org_id is also present"
		}
		if len(content.AccountsListed) != 1 {
			return "no_organization is true but accounts_listed is not the single-account fallback"
		}
	} else if content.OrgID == "" {
		return "organization_verified is true but neither org_id nor no_organization is present"
	}

	listed := make(map[string]struct{}, len(content.AccountsListed))
	for _, accountID := range content.AccountsListed {
		listed[accountID] = struct{}{}
	}
	for _, accountID := range content.AccountsScanned {
		if _, ok := listed[accountID]; !ok {
			return fmt.Sprintf("accounts_scanned contains account %s, which is absent from accounts_listed", accountID)
		}
	}
	for checkID, check := range content.Checks {
		for _, accountID := range content.AccountsListed {
			if _, ok := check.Accounts[accountID]; !ok {
				return fmt.Sprintf("check %s has no per-account result for listed account %s", checkID, accountID)
			}
		}
	}
	if content.SupabaseOrganizationID != "" || len(content.ProjectsListed) > 0 || len(content.ProjectsScanned) > 0 {
		if content.SupabaseOrganizationID == "" || len(content.ProjectsListed) == 0 {
			return "Supabase scope is incomplete: organization ID and projects_listed are required together"
		}
		projects := make(map[string]struct{}, len(content.ProjectsListed))
		for _, project := range content.ProjectsListed {
			projects[project] = struct{}{}
		}
		for _, project := range content.ProjectsScanned {
			if _, ok := projects[project]; !ok {
				return fmt.Sprintf("projects_scanned contains project %s, which is absent from projects_listed", project)
			}
		}
		for checkID, check := range content.Checks {
			if !strings.HasPrefix(checkID, "supabase.") {
				continue
			}
			for _, project := range content.ProjectsListed {
				if _, ok := check.Accounts[project]; !ok {
					return fmt.Sprintf("check %s has no per-project result for listed project %s", checkID, project)
				}
			}
		}
	}
	return ""
}

// handleLatest implements GET /v1/share/{token}: the buyer-facing link
// that always shows whatever the most recently ATTESTED verdict is for
// that token.
func (s *Server) handleLatest(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	if !s.resolveShareLink(w, r, token) {
		return
	}

	v, err := s.store.LatestVerdict(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "this token exists but has no verdicts yet")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load verdict")
		return
	}

	view, err := verdictToView(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render verdict")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleHistory implements GET /v1/share/{token}/history: every verdict
// for a token, newest attested first. Accepts an optional ?limit= query
// parameter (see store.defaultHistoryLimit / maxHistoryLimit for the
// bounds actually enforced).
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	if !s.resolveShareLink(w, r, token) {
		return
	}

	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = n
	}

	verdicts, err := s.store.VerdictHistory(r.Context(), token, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load verdict history")
		return
	}

	views := make([]verdictView, 0, len(verdicts))
	for _, v := range verdicts {
		view, err := verdictToView(v)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to render verdict")
			return
		}
		views = append(views, view)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":    token,
		"verdicts": views,
	})
}

// handleControlHistory is a compact, server-side convenience index for one
// check's per-account status timeline. It is intentionally not used as the
// buyer page's source of truth: that page fetches full verdict history and
// recomputes changes after independently verifying both attestations. This
// endpoint is useful to integrations that only need a control's status series.
func (s *Server) handleControlHistory(w http.ResponseWriter, r *http.Request) {
	token, checkID := r.PathValue("token"), r.PathValue("check_id")
	if !s.resolveShareLink(w, r, token) {
		return
	}
	verdicts, err := s.store.VerdictHistory(r.Context(), token, 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load verdict history")
		return
	}

	type transition struct {
		ScanID         string    `json:"scan_id"`
		AttestedAt     time.Time `json:"attested_at"`
		AccountID      string    `json:"account_id"`
		PreviousStatus string    `json:"previous_status,omitempty"`
		CurrentStatus  string    `json:"current_status"`
	}
	// VerdictHistory is newest-first. Walk oldest-first so each emitted
	// transition means "this is the status first observed at AttestedAt".
	previous := map[string]string{}
	var transitions []transition
	for i := len(verdicts) - 1; i >= 0; i-- {
		verdict := verdicts[i]
		var allChecks map[string]report.CheckOutput
		if err := json.Unmarshal(verdict.Checks, &allChecks); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to decode verdict checks")
			return
		}
		check, exists := allChecks[checkID]
		if !exists {
			continue // This scanner version did not include the requested control.
		}
		statuses := check.Accounts
		if len(statuses) == 0 {
			statuses = map[string]checks.Result{verdict.AccountID: check.Result}
		}
		accountIDs := make([]string, 0, len(statuses))
		for accountID := range statuses {
			accountIDs = append(accountIDs, accountID)
		}
		sort.Strings(accountIDs)
		for _, accountID := range accountIDs {
			current := statuses[accountID].Status
			prior, seen := previous[accountID]
			if !seen || prior != current {
				transitions = append(transitions, transition{ScanID: verdict.ScanID, AttestedAt: verdict.AttestedAt, AccountID: accountID, PreviousStatus: prior, CurrentStatus: current})
			}
			previous[accountID] = current
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "check_id": checkID, "transitions": transitions})
}

// handleQuestionnaireAutofill transforms one CSV/XLSX upload using the most
// recent attested verdict behind the share token. Uploaded questionnaire data
// is never persisted: it is read, transformed, returned, and then discarded.
func (s *Server) handleQuestionnaireAutofill(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !s.resolveShareLink(w, r, token) {
		return
	}
	if s.questionnaires == nil {
		writeError(w, http.StatusServiceUnavailable, "questionnaire autofill is not configured")
		return
	}

	v, err := s.store.LatestVerdict(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "this token exists but has no verdicts yet")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load latest verdict")
		return
	}
	var verdictChecks map[string]report.CheckOutput
	if err := json.Unmarshal(v.Checks, &verdictChecks); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to decode latest verdict checks")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxQuestionnaireUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid questionnaire upload: "+err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("questionnaire")
	if err != nil {
		writeError(w, http.StatusBadRequest, "multipart field questionnaire is required")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxQuestionnaireUploadBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read questionnaire upload: "+err.Error())
		return
	}
	if len(data) > maxQuestionnaireUploadBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "questionnaire exceeds 16 MiB")
		return
	}

	result, err := s.questionnaires.Autofill(questionnaire.AutofillInput{
		Filename:        header.Filename,
		Data:            data,
		AccountID:       v.AccountID,
		EvidenceURL:     s.buyerURL(token),
		AttestedAt:      v.AttestedAt,
		Checks:          verdictChecks,
		AccountsListed:  v.AccountsListed,
		AccountsScanned: v.AccountsScanned,
	})
	if err != nil {
		switch {
		case errors.Is(err, questionnaire.ErrUnsupportedFormat), errors.Is(err, questionnaire.ErrNoQuestionTable):
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		default:
			writeError(w, http.StatusUnprocessableEntity, "could not autofill questionnaire: "+err.Error())
		}
		return
	}

	reportJSON, _ := json.Marshal(result.Report)
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": result.Filename}))
	w.Header().Set("X-ZeroDock-Autofill-Report", base64.RawURLEncoding.EncodeToString(reportJSON))
	w.Header().Set("X-ZeroDock-Answered", strconv.Itoa(result.Report.Answered))
	w.Header().Set("X-ZeroDock-Partial", strconv.Itoa(result.Report.Partial))
	w.Header().Set("X-ZeroDock-Flagged", strconv.Itoa(result.Report.Flagged))
	w.Header().Set("X-ZeroDock-Needs-Human", strconv.Itoa(result.Report.NeedsHuman))
	w.Header().Set("X-ZeroDock-Hours-Saved", strconv.FormatFloat(result.Report.HoursSaved, 'f', 2, 64))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.Data)
}

// resolveShareLink is the shared "is this token even usable" check both
// GET handlers run before touching verdicts at all. It writes the
// appropriate error response itself and returns false if the token isn't
// usable, so callers can just do:
//
//	if !s.resolveShareLink(w, r, token) {
//	    return
//	}
//
// Three distinct outcomes, on purpose: a token that never existed is a
// plain 404 (nothing to see, never was). A token that existed and was
// explicitly REVOKED is a 410 Gone — different from 404 because it tells
// a client "this used to work and was deliberately killed", not "this
// never worked" — which matters if a buyer's bookmarked link suddenly
// stops resolving and they want to know why. Revoking a link never
// touches the verdicts underneath it (see share_links.revoked_at in
// migrations/0001_init.sql); it just stops THIS lookup from succeeding.
func (s *Server) resolveShareLink(w http.ResponseWriter, r *http.Request, token string) bool {
	exists, revoked, err := s.store.ShareLinkStatus(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to look up token")
		return false
	}
	if !exists {
		writeError(w, http.StatusNotFound, "unknown share token")
		return false
	}
	if revoked {
		writeError(w, http.StatusGone, "this share link has been revoked")
		return false
	}
	return true
}

// requiredFieldsMissing returns the name of the first required field
// missing from a submission, or "" if nothing is missing. Kept as one
// function so handleCreateVerdict's validation reads as a single
// straight-line check rather than a wall of individual if-statements.
func requiredFieldsMissing(sub report.Report) string {
	switch {
	case sub.ScanID == "":
		return "scan_id"
	case sub.ScannerVersion == "":
		return "scanner_version"
	case sub.AccountID == "":
		return "account_id"
	case sub.ResultsHash == "":
		return "results_sha384"
	case sub.Attestation == nil:
		return "attestation"
	case sub.Attestation.Doc == "":
		return "attestation.cose_sign1_base64"
	case sub.Attestation.Format == "":
		return "attestation.format"
	default:
		return ""
	}
}

// hashAttestedContent reproduces EXACTLY what cmd/scanner computed as
// results_sha384 — see internal/report's package comment for why this
// only works because both sides marshal the identical shared type.
func hashAttestedContent(content report.AttestedContent) string {
	encoded, err := json.Marshal(content)
	if err != nil {
		// AttestedContent's fields are all plain, always-marshalable
		// types (strings, bools, slices, and a map of a plain struct) —
		// this can only fail from a future change introducing a
		// non-marshalable field, which is a programming error, not a
		// runtime condition callers need to handle.
		panic(fmt.Sprintf("internal/api: marshal AttestedContent: %s", err))
	}
	sum := sha512.Sum384(encoded)
	return hex.EncodeToString(sum[:])
}

func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

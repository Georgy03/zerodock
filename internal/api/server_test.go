package api

import (
	"context"
	"errors"
	"sort"

	"github.com/Georgy03/zerodock/internal/store"
)

// fakeStore is an in-memory stand-in for *store.Store, used so handler
// tests can exercise every success/failure path without a real Postgres
// connection. It deliberately re-implements the SAME rules the real
// store enforces that handlers depend on (duplicate scan_id rejection,
// unknown-vs-revoked-vs-live token) — not a full SQL engine, just enough
// behavior for the handlers under test to see the same shape of
// responses a real database would give them.
type fakeStore struct {
	shareLinks      map[string]string // account_id -> token
	revoked         map[string]bool   // token -> revoked
	verdictsByToken map[string][]store.Verdict
	scanIDs         map[string]bool
	onboardings     map[string]store.Onboarding
	nextID          int64

	// forceErr, if set, is returned by every method — used to test the
	// "database is unavailable" 500 paths.
	forceErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		shareLinks:      make(map[string]string),
		revoked:         make(map[string]bool),
		verdictsByToken: make(map[string][]store.Verdict),
		scanIDs:         make(map[string]bool),
		onboardings:     make(map[string]store.Onboarding),
	}
}

func (f *fakeStore) CreateVerdict(_ context.Context, nv store.NewVerdict) (store.Verdict, error) {
	if f.forceErr != nil {
		return store.Verdict{}, f.forceErr
	}
	if f.scanIDs[nv.ScanID] {
		return store.Verdict{}, store.ErrDuplicateScan
	}

	token, ok := f.shareLinks[nv.AccountID]
	if !ok {
		token = "token-" + nv.AccountID
		f.shareLinks[nv.AccountID] = token
	}

	f.nextID++
	v := store.Verdict{
		ID:                   f.nextID,
		ShareToken:           token,
		ScannerVersion:       nv.ScannerVersion,
		OrganizationVerified: nv.OrganizationVerified,
		OrgID:                nv.OrgID,
		NoOrganization:       nv.NoOrganization,
		OrganizationWarning:  nv.OrganizationWarning,
		AccountsListed:       nv.AccountsListed,
		AccountsScanned:      nv.AccountsScanned,
		ScanID:               nv.ScanID,
		AccountID:            nv.AccountID,
		AttestedAt:           nv.AttestedAt,
		ScopeVerified:        nv.ScopeVerified,
		ScopeWarning:         nv.ScopeWarning,
		TimeVerified:         nv.TimeVerified,
		TimeWarning:          nv.TimeWarning,
		RequestedRegions:     nv.RequestedRegions,
		ScannedRegions:       nv.ScannedRegions,
		RegionsWarning:       nv.RegionsWarning,
		ResultsSHA384:        nv.ResultsSHA384,
		Checks:               nv.Checks,
		AttestationFormat:    nv.AttestationFormat,
		AttestationMock:      nv.AttestationMock,
		PCRs:                 nv.PCRs,
		AttestationRaw:       nv.AttestationRaw,
	}
	f.scanIDs[nv.ScanID] = true
	f.verdictsByToken[token] = append(f.verdictsByToken[token], v)
	return v, nil
}

func (f *fakeStore) ShareLinkStatus(_ context.Context, token string) (exists, revoked bool, err error) {
	if f.forceErr != nil {
		return false, false, f.forceErr
	}
	if _, ok := f.verdictsByToken[token]; ok {
		return true, f.revoked[token], nil
	}
	for _, t := range f.shareLinks {
		if t == token {
			return true, f.revoked[token], nil
		}
	}
	return false, false, nil
}

func (f *fakeStore) LatestVerdict(_ context.Context, token string) (store.Verdict, error) {
	if f.forceErr != nil {
		return store.Verdict{}, f.forceErr
	}
	vs := f.verdictsByToken[token]
	if len(vs) == 0 {
		return store.Verdict{}, store.ErrNotFound
	}
	// Newest ATTESTED first, matching the real store's ORDER BY
	// attested_at DESC.
	latest := vs[0]
	for _, v := range vs[1:] {
		if v.AttestedAt.After(latest.AttestedAt) {
			latest = v
		}
	}
	return latest, nil
}

func (f *fakeStore) VerdictHistory(_ context.Context, token string, limit int) ([]store.Verdict, error) {
	if f.forceErr != nil {
		return nil, f.forceErr
	}
	vs := append([]store.Verdict(nil), f.verdictsByToken[token]...)
	sort.Slice(vs, func(i, j int) bool { return vs[i].AttestedAt.After(vs[j].AttestedAt) })
	if limit > 0 && limit < len(vs) {
		vs = vs[:limit]
	}
	return vs, nil
}

func (f *fakeStore) CreateOnboarding(_ context.Context, customerAccountID string) (store.Onboarding, error) {
	if f.forceErr != nil {
		return store.Onboarding{}, f.forceErr
	}
	tenantID := "tenant-" + customerAccountID
	ob := store.Onboarding{TenantID: tenantID, CustomerAccountID: customerAccountID}
	if f.onboardings == nil {
		f.onboardings = make(map[string]store.Onboarding)
	}
	f.onboardings[tenantID] = ob
	return ob, nil
}

func (f *fakeStore) GetOnboarding(_ context.Context, tenantID string) (store.Onboarding, error) {
	if f.forceErr != nil {
		return store.Onboarding{}, f.forceErr
	}
	ob, ok := f.onboardings[tenantID]
	if !ok {
		return store.Onboarding{}, store.ErrNotFound
	}
	return ob, nil
}

// addSubjectOnly registers a token with no verdicts yet, so tests can
// exercise the "known token, nothing to show" path distinctly from
// "token never existed".
func (f *fakeStore) addSubjectOnly(accountID, token string) {
	f.shareLinks[accountID] = token
	if _, ok := f.verdictsByToken[token]; !ok {
		f.verdictsByToken[token] = nil
	}
}

// revokeToken marks a token revoked, for tests exercising the 410 path.
func (f *fakeStore) revokeToken(token string) {
	f.revoked[token] = true
}

var errFakeStoreForced = errors.New("forced store failure for testing")

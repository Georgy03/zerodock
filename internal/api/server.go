// Package api is the week-5 HTTP backend: it accepts scan reports
// (attestation + results) from a running enclave, verifies them
// server-side (internal/verify), persists the verified ones append-only
// (internal/store), and serves them back out to buyers via a share link.
//
// "Ordinary Go" on purpose: routing is the standard library's
// http.ServeMux (Go 1.22+ supports method + path-parameter patterns like
// "GET /v1/share/{token}" directly — no router dependency needed), and
// there's no framework, middleware stack, or ORM here — just handlers
// that call into internal/verify and internal/store.
//
// SCOPE NOTE — freshness is NOT this package's job. internal/verify
// confirms a document is AUTHENTIC (genuinely signed, correctly chained)
// evaluated at its own attested timestamp, which deliberately says
// nothing about whether that timestamp is recent — see the big comment
// on verifyChain in internal/verify for why those are different
// questions. This package does not reject old-but-genuine submissions,
// and GET /v1/share/{token} does not hide or flag a stale verdict as
// stale. Deciding "is this recent enough to show as current" belongs to
// whoever renders a verdict for a human to look at (the eventual buyer
// page), with its own explicit window — not baked into ingest or storage
// here. This is a known, deliberate gap in this package today, not an
// oversight.
package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/Georgy03/zerodock/internal/store"
	"github.com/Georgy03/zerodock/internal/verify"
)

// maxRequestBodyBytes caps how large a single POST /v1/verdicts body can
// be. A scan report is normally well under a megabyte, so this is
// generous headroom, not a tight fit — its real job is making sure a
// malicious or broken client can't make this endpoint read an unbounded
// amount of data into memory.
const maxRequestBodyBytes = 8 << 20 // 8 MiB

// verdictStore is the slice of *store.Store this package actually needs.
// Handlers depend on this INTERFACE, not the concrete *store.Store type,
// specifically so handler tests (server_test.go) can exercise every
// success/failure path with an in-memory fake instead of needing a real
// Postgres connection — the same reasoning behind, e.g., VsockDialer's
// error paths being tested without real vsock hardware elsewhere in this
// project. *store.Store satisfies this automatically; nothing about
// internal/store needs to know this interface exists.
type verdictStore interface {
	CreateVerdict(ctx context.Context, nv store.NewVerdict) (store.Verdict, error)
	ShareLinkStatus(ctx context.Context, token string) (exists, revoked bool, err error)
	LatestVerdict(ctx context.Context, token string) (store.Verdict, error)
	VerdictHistory(ctx context.Context, token string, limit int) ([]store.Verdict, error)
}

// Server holds everything the HTTP handlers need: the database (via
// verdictStore), the verification policy (internal/verify.Options —
// notably whether mock attestations are accepted at all), and the public
// base URL used to build share links in POST responses.
type Server struct {
	store      verdictStore
	verifyOpts verify.Options
	publicBase string

	// verifyFn defaults to verify.Verify — swappable in tests so
	// handler behavior can be exercised without needing a real signed
	// attestation document for every test case.
	verifyFn func(signedDoc []byte, opts verify.Options) (verify.Outcome, error)
}

// New builds a Server backed by a real *store.Store. publicBaseURL is
// used only to construct the share_url convenience field in POST
// /v1/verdicts responses (e.g. "https://verify.zerodock.example") —
// trailing slashes are trimmed, so either form works.
func New(st *store.Store, verifyOpts verify.Options, publicBaseURL string) *Server {
	return &Server{
		store:      st,
		verifyOpts: verifyOpts,
		publicBase: strings.TrimRight(publicBaseURL, "/"),
		verifyFn:   verify.Verify,
	}
}

// Routes builds the HTTP handler for this server. Kept separate from New
// so cmd/api/main.go can wrap the result in its own middleware (logging,
// timeouts, etc.) before handing it to http.Server.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/verdicts", s.handleCreateVerdict)
	mux.HandleFunc("GET /v1/share/{token}", s.handleLatest)
	mux.HandleFunc("GET /v1/share/{token}/history", s.handleHistory)
	return mux
}

func (s *Server) shareURL(token string) string {
	if s.publicBase == "" {
		return "/v1/share/" + token
	}
	return s.publicBase + "/v1/share/" + token
}

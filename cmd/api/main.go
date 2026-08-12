// Command api is the week-5 backend server: it exposes the three HTTP
// endpoints defined in internal/api (verdict ingest, share/history reads,
// and questionnaire autofill), backed by
// Postgres (internal/store) and server-side attestation verification
// (internal/verify).
//
// Configuration is entirely via environment variables — no config file,
// no flags — since that's the ordinary way to configure a small Go
// service meant to run as a container/systemd unit rather than be
// invoked interactively the way cmd/scanner is.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Georgy03/zerodock/internal/api"
	"github.com/Georgy03/zerodock/internal/questionnaire"
	"github.com/Georgy03/zerodock/internal/store"
	"github.com/Georgy03/zerodock/internal/verify"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("zerodock-api: %s", err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// A startup context, separate from any individual request's context —
	// just long enough to establish the database connection before we
	// start serving traffic.
	startupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := store.Open(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	if cfg.AllowMockAttestation {
		// Loud on purpose: accepting mock attestations means this
		// server's verdicts don't actually prove hardware isolation —
		// that's fine for a staging environment, but is exactly the
		// kind of configuration that should never be silently true in
		// production.
		log.Println("zerodock-api: WARNING — ZERODOCK_ALLOW_MOCK_ATTESTATION is enabled; this server will accept mock (non-hardware) attestations as valid verdicts")
	}

	questionnaireConfig, err := questionnaire.LoadConfig(cfg.QuestionnaireMappingsFile)
	if err != nil {
		return fmt.Errorf("load questionnaire mappings: %w", err)
	}
	srv := api.New(st, verify.Options{AllowMock: cfg.AllowMockAttestation}, cfg.PublicBaseURL, cfg.BuyerBaseURL, questionnaire.NewEngine(questionnaireConfig))

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Routes(),
		// Explicit timeouts, rather than the standard library's
		// "no timeout at all" default — a slow or hostile client
		// shouldn't be able to hold a connection open indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// serveErr carries http.Server.ListenAndServe's result out of its own
	// goroutine so we can select on it alongside "an OS signal arrived" —
	// the standard pattern for a server that supports graceful shutdown.
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("zerodock-api: listening on %s", cfg.ListenAddr)
		serveErr <- httpServer.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil

	case <-stop:
		log.Println("zerodock-api: shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// config holds every environment-variable-derived setting this server
// needs. Collecting them into one struct, read once at startup, means the
// rest of the program never calls os.Getenv directly — one place to see
// every knob this service has.
type config struct {
	// DatabaseURL is a standard Postgres connection string (e.g.
	// "postgres://zerodock_app:PASSWORD@host:5432/zerodock"). It should
	// authenticate as the RESTRICTED zerodock_app role created in
	// migrations/0001_init.sql — never the migration/owner role — so the
	// append-only guarantee on the verdicts table actually holds for
	// this running server.
	DatabaseURL string

	// ListenAddr is the address net/http listens on, e.g. ":8080".
	ListenAddr string

	// PublicBaseURL builds share URLs returned by verdict ingest and written
	// into questionnaire evidence cells. Optional — if unset, request host
	// information is used for questionnaire evidence URLs.
	PublicBaseURL string

	// BuyerBaseURL is the public browser-verifier origin. Questionnaire
	// evidence must point here, never at the private JSON API.
	BuyerBaseURL string

	// AllowMockAttestation controls whether this server accepts
	// attestations that verify successfully but chain to a mock root
	// instead of the real AWS Nitro root — see internal/verify.Options
	// and its big comment on what "mock" means here. This should be
	// TRUE only in development/staging.
	AllowMockAttestation bool

	// QuestionnaireMappingsFile optionally replaces the embedded CAIQ/SOC 2
	// mapping data and can contain per-account overrides.
	QuestionnaireMappingsFile string
}

func loadConfig() (config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return config{}, fmt.Errorf("DATABASE_URL is required")
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	allowMock := false
	if raw := os.Getenv("ZERODOCK_ALLOW_MOCK_ATTESTATION"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return config{}, fmt.Errorf("ZERODOCK_ALLOW_MOCK_ATTESTATION: %q is not a valid boolean: %w", raw, err)
		}
		allowMock = parsed
	}
	buyerBaseURL := strings.TrimSpace(os.Getenv("BUYER_BASE_URL"))
	if buyerBaseURL == "" {
		return config{}, fmt.Errorf("BUYER_BASE_URL is required so questionnaire evidence links cannot silently point at the private API")
	}
	parsedBuyerURL, err := url.Parse(buyerBaseURL)
	if err != nil || parsedBuyerURL.Scheme == "" || parsedBuyerURL.Host == "" {
		return config{}, fmt.Errorf("BUYER_BASE_URL must be an absolute http(s) URL")
	}
	if parsedBuyerURL.Scheme != "http" && parsedBuyerURL.Scheme != "https" {
		return config{}, fmt.Errorf("BUYER_BASE_URL must use http or https")
	}

	return config{
		DatabaseURL:               dbURL,
		ListenAddr:                listenAddr,
		PublicBaseURL:             os.Getenv("PUBLIC_BASE_URL"),
		BuyerBaseURL:              strings.TrimRight(buyerBaseURL, "/"),
		AllowMockAttestation:      allowMock,
		QuestionnaireMappingsFile: os.Getenv("QUESTIONNAIRE_MAPPINGS_FILE"),
	}, nil
}

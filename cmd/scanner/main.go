// Command scanner is the actual program you run. Its job, in order, is:
//  1. Open an attester (mock, for local testing; real NSM hardware, inside
//     an enclave) and a network path (normal TCP; vsock, inside an
//     enclave) — see internal/attest and internal/transport.
//  2. Ask that attester for a trustworthy "what time is it right now",
//     since an enclave's own guest-OS clock can't be trusted.
//  3. Figure out which AWS account we're allowed to look at.
//  4. Run every registered check against that account.
//  5. Bundle all the results together and compute a fingerprint (hash) of
//     them.
//  6. Seal that fingerprint inside a signed attestation document.
//  7. Print the whole thing out as one JSON document — the exact shape
//     internal/report.Report defines, and the exact shape internal/api's
//     POST /v1/verdicts endpoint expects to receive back.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Georgy03/zerodock/internal/attest"
	"github.com/Georgy03/zerodock/internal/buildinfo"
	"github.com/Georgy03/zerodock/internal/checks"
	"github.com/Georgy03/zerodock/internal/providers"
	"github.com/Georgy03/zerodock/internal/report"
	"github.com/Georgy03/zerodock/internal/transport"
)

func main() {
	// This defines a command-line flag: running the program with
	// `--mock-attest` (or `--mock-attest=true`) switches to local
	// development mode: the pretend attester AND a normal internet
	// connection. It DEFAULTS TO FALSE, meaning "I'm running for real
	// inside a Nitro Enclave" — the real NSM attester AND vsock
	// networking, since those are the only things that work there.
	// Everything below picks its networking and credentials strategy
	// based on this SAME flag, rather than adding separate flags for
	// each, because in practice the two always travel together: you
	// can't have vsock without an enclave, and you can't have /dev/nsm
	// without one either.
	mockAttest := flag.Bool("mock-attest", false, "use the mock attester and a normal network connection, for local development outside an enclave (default: real NSM attester + vsock networking)")
	regionsFlag := flag.String("regions", "us-east-1,us-east-2", "comma-separated AWS regions to scan")
	flag.Parse()
	requestedRegions, err := parseRegions(*regionsFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "zerodock: "+err.Error())
		os.Exit(2)
	}

	if err := run(*mockAttest, requestedRegions); err != nil {
		// Print errors to STDERR (the "error output" stream) rather
		// than mixing them into the JSON we print on success, and
		// exit with a non-zero status code so scripts calling this
		// program can tell it failed.
		fmt.Fprintln(os.Stderr, "zerodock: "+err.Error())
		os.Exit(1)
	}
}

// run does the actual work. It's kept separate from main() so it can
// return a normal Go error instead of needing to call os.Exit() itself —
// that keeps error-handling in exactly one place (main).
func run(mockAttest bool, requestedRegions []string) error {
	ctx := context.Background()

	// Open the selected attester before making any AWS calls. In an
	// enclave this fails fast if /dev/nsm is unavailable, and a successful
	// one-shot run therefore also proves that the NSM request completed.
	var attester attest.Attester
	var format string
	if mockAttest {
		m, err := attest.NewMockAttester()
		if err != nil {
			return fmt.Errorf("init mock attester: %w", err)
		}
		attester = m
		format = "COSE_Sign1/ES384 (mock attester)"
	} else {
		n, err := attest.NewNSMAttester()
		if err != nil {
			return fmt.Errorf("init NSM attester: %w", err)
		}
		defer n.Close()
		attester = n
		format = "COSE_Sign1/ES384 (AWS Nitro NSM)"
	}

	// Get a trustworthy "now" from the attester before doing anything
	// that depends on the current time — including running the checks
	// below (aws.iam.key_age needs it) and stamping the report itself.
	// See trustedNow and attest.ExtractTimestamp for why an enclave's own
	// guest-OS clock can't be used for this directly.
	now, timeVerified, timeWarning := trustedNow(attester)

	// Pick how to reach the network: TCPDialer outside an enclave (a
	// normal internet connection), VsockDialer inside one (the only path
	// out of an enclave — see internal/transport for the full
	// explanation). This single choice is what NewHTTPClient below plugs
	// into every AWS SDK client we build.
	var dialer transport.Dialer
	if mockAttest {
		dialer = transport.NewTCPDialer()
	} else {
		dialer = transport.NewVsockDialer()
	}

	httpClient, err := transport.NewHTTPClient(dialer)
	if err != nil {
		return fmt.Errorf("build HTTP client: %w", err)
	}

	configOpts := []func(*config.LoadOptions) error{
		config.WithHTTPClient(httpClient),
	}

	// Inside the enclave there is no IMDS reachable to auto-detect a
	// region from, and no ~/.aws/config file to read one from either (the
	// container image is `scratch` — there is no filesystem beyond what
	// we explicitly embedded). So the region has to come from an
	// environment variable baked into the image at deploy time, with a
	// hardcoded fallback so the scanner still starts if that's missing.
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	configOpts = append(configOpts, config.WithRegion(region))

	if !mockAttest {
		// Inside the enclave: the parent instance already has real AWS
		// credentials, from its own IAM instance role. It hands a
		// temporary copy to us over a dedicated vsock connection, once,
		// at startup — see transport.FetchCredentials and
		// deploy/serve-credentials.py for the parent-side half of this.
		//
		// This is safe for the same reason all the other AWS traffic is
		// safe: TLS terminates INSIDE this enclave, not on the parent.
		// The parent can hand us credentials, but it can never read or
		// alter what we subsequently do with them, because it never sees
		// the decrypted contents of a single API request or response —
		// see the SECURITY NOTE on transport.Credentials for the full
		// explanation.
		vsockDialer, ok := dialer.(*transport.VsockDialer)
		if !ok {
			return fmt.Errorf("internal error: expected a VsockDialer when not using --mock-attest")
		}
		creds, err := transport.FetchCredentials(ctx, vsockDialer)
		if err != nil {
			return fmt.Errorf("fetch credentials from parent instance: %w", err)
		}
		configOpts = append(configOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		))
	}
	// Outside the enclave (--mock-attest): no credentials option is
	// added above, so the AWS SDK falls back to its normal default
	// credential chain (environment variables, ~/.aws/credentials, SSO,
	// an assumed role, etc.) — unchanged from before vsock existed.

	cfg, err := config.LoadDefaultConfig(ctx, configOpts...)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	// Record the real regional scope once for the report. RunAcrossRegions
	// performs the same intersection for each regional check before it calls
	// that check, so a region can never be scanned merely because it appeared
	// in the command-line list.
	scannedRegions := []string{}
	regionsWarning := ""
	enabledRegions, regionsErr := providers.EnabledRegions(ctx, cfg)
	if regionsErr != nil {
		regionsWarning = fmt.Sprintf("could not list AWS-enabled regions: %s", regionsErr)
	} else {
		scannedRegions = providers.IntersectRequestedRegions(requestedRegions, enabledRegions)
		if unavailable := providers.UnavailableRequestedRegions(requestedRegions, enabledRegions); len(unavailable) > 0 {
			regionsWarning = "requested regions not enabled for this account: " + strings.Join(unavailable, ", ")
		}
	}
	ctx = checks.WithRequestedRegions(ctx, requestedRegions)

	// Ask AWS "who am I, according to these credentials?" — mainly so we
	// can record which AWS account this scan covers in the report. This
	// call has NO effect on whether the checks below run: even if it
	// fails, the scan still proceeds — it just can't claim to know its
	// own scope, which we record explicitly below instead of leaving
	// silent.
	stsClient := sts.NewFromConfig(cfg)
	identity, identityErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})

	rep := report.Report{
		ScanID:    newScanID(),
		Timestamp: now,
		AttestedContent: report.AttestedContent{
			ScannerVersion:   buildinfo.Version,
			TimeVerified:     timeVerified,
			TimeWarning:      timeWarning,
			RequestedRegions: requestedRegions,
			ScannedRegions:   scannedRegions,
			RegionsWarning:   regionsWarning,
			Checks:           make(map[string]report.CheckOutput, len(checks.All)),
		},
	}
	if identityErr == nil {
		rep.AccountID = awsToString(identity.Account)
		rep.ScopeVerified = true
	} else {
		rep.ScopeVerified = false
		rep.ScopeWarning = fmt.Sprintf("could not confirm which AWS account this scan covers: %s", identityErr)
	}

	// This is the heart of the program: loop over every check that
	// registered itself (see checks.All in internal/checks/types.go),
	// run it, and store its result. Because every check follows the
	// exact same Check/Result shape, this loop works no matter how many
	// checks exist or what each one individually does. now is threaded
	// through here rather than left for each check to determine itself —
	// see the comment on Check.Run in internal/checks/types.go.
	for _, check := range checks.All {
		result, err := check.Run(ctx, cfg, now)
		if err != nil {
			// In normal operation, a check reports problems through
			// Result.Status ("error"), not by returning a Go error —
			// but just in case a check is buggy and returns one
			// anyway, we still record something useful instead of
			// crashing or silently dropping that check from the
			// report.
			result = checks.Result{Status: checks.StatusError, Findings: []string{err.Error()}}
		}
		rep.Checks[check.ID] = report.CheckOutput{
			Title:  check.Title,
			Tier:   check.Tier,
			Result: result,
		}
	}

	// Turn the attested claim (which account, whether we could even
	// confirm that, whether the clock was trustworthy, and every check's
	// result) into JSON bytes, and take a SHA-384 fingerprint (hash) of
	// those bytes. A hash is a short, fixed-length "fingerprint" of some
	// data: if even a single character changed, the hash would come out
	// completely different. By sealing THIS hash inside the attestation
	// (below), anyone checking the attestation later can confirm the
	// account, scope, and check results are exactly what was originally
	// scanned — nothing added, removed, or edited. Marshaling
	// rep.AttestedContent directly (rather than rebuilding an equivalent
	// struct by hand) is what guarantees the backend can reproduce this
	// exact hash later: both sides marshal the SAME shared type — see
	// internal/report for why that has to be true byte-for-byte.
	resultsBlob, err := json.Marshal(rep.AttestedContent)
	if err != nil {
		return fmt.Errorf("marshal results for hashing: %w", err)
	}
	sum := sha512.Sum384(resultsBlob) // Sum384 = SHA-384, from the SHA-512 family of hash functions
	rep.ResultsHash = hex.EncodeToString(sum[:])

	// The nonce must come from whoever is REQUESTING the attestation,
	// not from the attester itself — that's what proves the resulting
	// document is fresh rather than an old one being replayed. Here,
	// this CLI run is the requester, so we generate one random nonce for
	// this scan.
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate attestation nonce: %w", err)
	}
	// Seal the results hash (not the whole report) inside the
	// attestation — see internal/attest/mock.go (or nsm.go) for what
	// actually happens here. This is a SEPARATE, later Attest() call from
	// the one trustedNow made above — that one was only ever used to read
	// a timestamp back out, not to seal anything.
	doc, err := attester.Attest(sum[:], nonce)
	if err != nil {
		return fmt.Errorf("attest results: %w", err)
	}
	rep.Attestation = &report.AttestationOutput{
		Format: format,
		Doc:    base64.StdEncoding.EncodeToString(doc),
	}

	// Print the whole report as nicely-indented JSON. Inside a real
	// enclave (without --debug-mode) this stdout is invisible to anyone —
	// but it costs nothing to still do it, and it's useful when debugging
	// with --debug-mode on. Either way, it is NOT how the report actually
	// gets to anyone in production; see the vsock delivery just below for
	// that.
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	fmt.Println(string(out))

	if !mockAttest {
		// Outside of --debug-mode, the print above is the scan's only
		// OTHER output, and nobody can see it — this vsock delivery is
		// the ONLY way the report reaches anyone. That makes a failed
		// delivery equivalent to a failed scan, not a "silent success":
		// deliverReport retries a couple of times against a transient
		// vsock hiccup, and if it still fails, returns an error here that
		// makes main() exit non-zero instead of pretending everything
		// went fine.
		vsockDialer, ok := dialer.(*transport.VsockDialer)
		if !ok {
			return fmt.Errorf("internal error: expected a VsockDialer when not using --mock-attest")
		}
		if err := deliverReport(ctx, vsockDialer, out); err != nil {
			return fmt.Errorf("deliver report to parent: %w", err)
		}
	}

	return nil
}

// reportDeliveryAttempts and reportDeliveryBackoff control how hard
// deliverReport tries before giving up. The enclave has no OTHER way to
// get its results out (see the comment where this is called), so a
// transient vsock hiccup shouldn't fail the whole run — but a report that
// genuinely can never be delivered should, rather than the program
// silently exiting 0 having produced nothing anyone will ever see.
const (
	reportDeliveryAttempts = 3 // 1 initial attempt + 2 retries, per the spec for this feature
	reportDeliveryBackoff  = 500 * time.Millisecond
)

// deliverReport sends the finished report to the parent's report collector
// (deploy/collect-report.py) over vsock, retrying with a short backoff
// between attempts. It returns the LAST error seen if every attempt fails,
// wrapped with how many attempts were made — so the final error message
// tells you both what went wrong and that retrying didn't help.
func deliverReport(ctx context.Context, dialer *transport.VsockDialer, payload []byte) error {
	var lastErr error
	for attempt := 1; attempt <= reportDeliveryAttempts; attempt++ {
		err := transport.SendReport(ctx, dialer, payload)
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt < reportDeliveryAttempts {
			// Back off a little longer each retry (500ms, then 1s)
			// rather than hammering a proxy that might just need a
			// moment to come up.
			time.Sleep(reportDeliveryBackoff * time.Duration(attempt))
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", reportDeliveryAttempts, lastErr)
}

func parseRegions(value string) ([]string, error) {
	seen := make(map[string]struct{})
	regions := make([]string, 0)
	for _, part := range strings.Split(value, ",") {
		region := strings.TrimSpace(part)
		if region == "" {
			continue
		}
		if _, ok := seen[region]; ok {
			continue
		}
		seen[region] = struct{}{}
		regions = append(regions, region)
	}
	if len(regions) == 0 {
		return nil, fmt.Errorf("--regions must contain at least one region")
	}
	return regions, nil
}

// trustedNow asks the attester for a throwaway attestation document purely
// to read a trustworthy timestamp back out of it (see
// attest.ExtractTimestamp), instead of calling time.Now() directly. If
// anything along the way fails, it falls back to time.Now() but says so
// honestly via the returned bool/string, rather than silently returning a
// value that looks just as trustworthy as a real one.
func trustedNow(attester attest.Attester) (now time.Time, verified bool, warning string) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return time.Now().UTC(), false, fmt.Sprintf("could not generate nonce for time-sync attestation: %s", err)
	}

	doc, err := attester.Attest([]byte("zerodock-time-sync"), nonce)
	if err != nil {
		return time.Now().UTC(), false, fmt.Sprintf("could not obtain a hardware-attested timestamp: %s", err)
	}

	ts, err := attest.ExtractTimestamp(doc)
	if err != nil {
		return time.Now().UTC(), false, fmt.Sprintf("could not read timestamp from attestation document: %s", err)
	}

	return ts, true, ""
}

// newScanID makes a random, unique-enough ID to identify this particular
// scan run (16 random bytes, written out as a 32-character hex string).
func newScanID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// awsToString safely reads a *string (a pointer to a string, which the AWS
// SDK uses everywhere to represent "this field might be missing"). If the
// pointer is nil (missing), we return an empty string instead of crashing.
func awsToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

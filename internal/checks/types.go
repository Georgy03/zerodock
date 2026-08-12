// Package checks defines what a "check" is in ZeroDock, and keeps a list of
// every check that exists. Think of a check as a small robot inspector: you
// give it your AWS account, and it looks at one specific thing (like "are
// any of my storage disks unencrypted?") and reports back what it found.
package checks

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Tier tells us HOW MUCH we should trust a check's answer. This is
// ZeroDock's honesty mechanism: it's not about how much work the check did,
// it's about WHO is vouching for the fact.
//
//   - ProviderAttested: a party the account owner doesn't control — AWS
//     itself — is reporting this state. Whether we read one field
//     (StorageEncrypted) or combine several of AWS's own answers together
//     (public access block + bucket policy status), AWS is still the one
//     asserting the underlying facts. We trust it because AWS has no
//     incentive to lie to us about the account owner's own resources.
//   - ActivelyProbed: we didn't just read a claim, we tested it — a
//     challenge/response over the network against the resource itself
//     (e.g. trying to connect with sslmode=disable and confirming the
//     server actually rejects it, rather than trusting a config flag that
//     says it should).
//   - InfraOnly: we verified the outer envelope via a cloud API (e.g. "this
//     EC2 instance's EBS volume is encrypted") but have no way to verify
//     what's happening inside the resource itself (e.g. a self-hosted
//     Postgres server's own disk encryption, which AWS can't see into).
//
// None of the checks in this build are ActivelyProbed or InfraOnly —
// everything here reads AWS-attested facts. Those tiers start being used
// once self-hosted database checks are added later.
type Tier string

const (
	ProviderAttested Tier = "provider_attested"
	ActivelyProbed   Tier = "actively_probed"
	InfraOnly        Tier = "infra_only"
)

// Result holds everything a single check found. Every check, no matter what
// it inspects, always returns one of these — that consistency is what lets
// cmd/scanner run every check the exact same way and combine their
// answers into one report.
type Result struct {
	// Status is one of "pass" (no problems found), "fail" (problems
	// found — see Findings), or "error" (we couldn't even finish the
	// check, usually because of a missing AWS permission).
	Status string `json:"status"`

	// Findings is a list of plain-English sentences describing each
	// problem (or error) the check ran into. Each sentence should be
	// specific enough that a human can go fix it — e.g. it names the
	// exact AWS resource ID and region involved.
	Findings []string `json:"findings"`

	// Count is how many resources this check actually looked at (not
	// just how many were "bad"). Useful for sanity-checking that the
	// check actually ran against something, instead of silently
	// examining zero resources.
	Count int `json:"count"`

	// Region is only set for checks that are naturally tied to a single
	// AWS region. Most checks look across every region, so this is often
	// left blank — the region for each finding is instead written
	// directly into that finding's sentence.
	Region string `json:"region,omitempty"`
}

// These are the only three valid values for Result.Status. Using named
// constants instead of typing "pass"/"fail"/"error" by hand everywhere
// means the compiler catches typos for us.
const (
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusError = "error"
)

// Check bundles together everything you need to know about one inspection:
// a short machine-readable name (ID), a human-readable name (Title), how
// much to trust its answer (Tier), and the actual function that performs
// the inspection (Run).
type Check struct {
	// ID is a short, dotted, machine-friendly name, e.g. "aws.ebs.encryption".
	// Tools and scripts can key off this to find a specific check's result.
	ID string

	// Title is a short sentence describing the check for humans, e.g.
	// "Unencrypted EBS volumes".
	Title string

	Tier Tier

	// Run is the actual function that talks to AWS and produces a
	// Result. It takes a context (used to cancel/time out the call), an
	// AWS config (which holds credentials and, usually, a starting
	// region), and now — the current time, as the CALLER determined it,
	// not as this check would determine it itself.
	//
	// WHY now IS A PARAMETER INSTEAD OF EACH CHECK JUST CALLING
	// time.Now(): inside a Nitro Enclave, the guest OS's clock cannot be
	// trusted (no battery-backed clock, no network for NTP) — but the
	// enclave's attestation document carries a timestamp from the Nitro
	// hypervisor's own clock, which CAN be trusted. cmd/scanner fetches
	// that trustworthy timestamp once, up front (see
	// attest.ExtractTimestamp), and passes it down to every check as
	// now. Only one check currently reads it (aws.iam.key_age, which
	// needs "now" to compute a key's age) — the rest simply ignore the
	// parameter, which is fine: an unused function parameter isn't a
	// compile error in Go, only an unused local variable is.
	Run func(ctx context.Context, cfg aws.Config, now time.Time) (Result, error)
}

// All is the master list of every check ZeroDock knows about. Each check
// file adds itself to this list automatically when the program starts (see
// the Register function below and the init() function at the top of each
// check's file). cmd/scanner then just loops over All and runs everything
// in it — nobody has to remember to manually list every check anywhere.
var All []Check

// Register adds one check to the All list. Every check file calls this
// exactly once, inside its own init() function, so the check "shows up"
// automatically as soon as its file is compiled into the program.
func Register(c Check) {
	All = append(All, c)
}

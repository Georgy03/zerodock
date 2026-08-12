package checks

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"

	"github.com/Georgy03/zerodock/internal/providers"
)

type requestedRegionsContextKey struct{}

// WithRequestedRegions adds the caller's intended regional scope to a scan
// context. RunAcrossRegions intersects this scope with AWS's enabled regions
// before it invokes a regional check.
func WithRequestedRegions(ctx context.Context, regions []string) context.Context {
	return context.WithValue(ctx, requestedRegionsContextKey{}, append([]string(nil), regions...))
}

func requestedRegions(ctx context.Context) []string {
	regions, _ := ctx.Value(requestedRegionsContextKey{}).([]string)
	return regions
}

// RegionFunc is the shape of a function that inspects ONE AWS region and
// reports what it found there. Most of our checks (EBS volumes, security
// groups, RDS databases, etc.) are naturally split up by region — AWS
// itself keeps each region's resources separate — so instead of writing
// "loop over every region" logic 8 separate times, every regional check
// just writes one of these functions and hands it to RunAcrossRegions
// below, which does the looping for it.
//
// It returns:
//   - findings: one string per problem found in this region
//   - count: how many resources were examined in this region
//   - err: non-nil if something went wrong (usually a permissions error)
type RegionFunc func(ctx context.Context, regionalCfg aws.Config) (findings []string, count int, err error)

// RunAcrossRegions is a helper that does the repetitive part of a regional
// check for you:
//  1. Ask AWS which regions are turned on for this account.
//  2. Call fn once for each of those regions.
//  3. Collect all the findings and counts together into one Result.
//
// If fn fails in ANY region (most commonly because the AWS credentials
// don't have permission to make that API call), we do NOT just quietly
// skip that region and pretend everything is fine. Instead the whole
// check's Status becomes "error", and the specific reason is added to
// Findings — so a missing permission is always visible, never hidden.
func RunAcrossRegions(ctx context.Context, cfg aws.Config, fn RegionFunc) (Result, error) {
	// Step 1: find out which regions this AWS account actually uses.
	// Some AWS regions are "opt-in" and disabled by default, so we only
	// want to scan regions that are actually turned on.
	enabledRegions, err := providers.EnabledRegions(ctx, cfg)
	if err != nil {
		return Result{
			Status:   StatusError,
			Findings: []string{fmt.Sprintf("list regions: %s", describeErr(err))},
		}, nil
	}
	regions := providers.IntersectRequestedRegions(requestedRegions(ctx), enabledRegions)
	if len(regions) == 0 {
		return Result{
			Status:   StatusError,
			Findings: []string{"none of the requested regions are enabled for this AWS account"},
		}, nil
	}

	var findings []string // problems found, from every region combined
	total := 0            // total number of resources looked at

	// regionsByErrorMessage groups regions by the EXACT error message
	// they failed with. Most permission problems (a missing IAM policy
	// statement, a service control policy, etc.) apply account-wide, so
	// the same "AccessDenied: ..." message tends to show up in every
	// single region — for an account with 17 enabled regions, that would
	// otherwise mean 17 near-identical lines in the report. Grouping
	// first lets us print ONE line per distinct message instead.
	regionsByErrorMessage := make(map[string][]string)

	// Step 2: visit every region one at a time and run the check there.
	for _, region := range regions {
		// Make a copy of the AWS config pointed at this specific region.
		// (We copy instead of mutating the original so regions don't
		// interfere with each other.)
		regionalCfg := providers.ForRegion(cfg, region)

		regionFindings, count, err := fn(ctx, regionalCfg)
		if err != nil {
			// Something went wrong in this region (e.g. "access
			// denied"). Remember which region hit which message, and
			// move on to the next region rather than stopping the
			// whole scan.
			msg := describeErr(err)
			regionsByErrorMessage[msg] = append(regionsByErrorMessage[msg], region)
			continue
		}

		findings = append(findings, regionFindings...)
		total += count
	}

	// Step 3: decide the final status.
	// If ANY region had an error, the whole check is reported as
	// "error" — we never want a permissions problem to look like a
	// clean "pass".
	if len(regionsByErrorMessage) > 0 {
		return Result{
			Status:   StatusError,
			Findings: append(findings, collapseRegionErrors(regionsByErrorMessage)...),
			Count:    total,
		}, nil
	}

	// No errors: it's a "fail" if we found any problems, otherwise a
	// clean "pass".
	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: total}, nil
}

// collapseRegionErrors turns "which regions failed with which message" into
// the final list of finding strings we print. It's pulled out of
// RunAcrossRegions as its own function specifically so it can be unit
// tested without needing a real (or mocked) AWS API call — everything it
// does is plain string/slice manipulation.
//
// A single region with a message gets named directly:
//
//	"us-west-2: AccessDenied: ..."
//
// The SAME message shared by multiple regions gets collapsed into one
// line instead of one line per region:
//
//	"failed in 17 regions: AccessDenied: ..."
func collapseRegionErrors(regionsByErrorMessage map[string][]string) []string {
	errs := make([]string, 0, len(regionsByErrorMessage))
	for msg, regionsWithThisError := range regionsByErrorMessage {
		if len(regionsWithThisError) == 1 {
			// Only one region hit this — naming it is more useful
			// than a "failed in 1 region" count.
			errs = append(errs, fmt.Sprintf("%s: %s", regionsWithThisError[0], msg))
			continue
		}
		// The same error hit multiple regions: collapse them into one
		// line instead of repeating the message per region.
		errs = append(errs, fmt.Sprintf("failed in %d regions: %s", len(regionsWithThisError), msg))
	}
	// Map iteration order is random in Go, so without sorting, the same
	// underlying errors could print in a different order on every run —
	// sort for stable, reproducible output.
	sort.Strings(errs)
	return errs
}

// describeErr turns an AWS error into a short, readable string like
// "AccessDenied: User is not authorized to perform ec2:DescribeVolumes".
// AWS errors normally come back as a generic Go `error`, but the AWS SDK
// tags them with extra structured info (an error "code" and "message") if
// you know how to unwrap it — that's what this function does. If the error
// isn't an AWS API error at all, we just fall back to its normal message.
func describeErr(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return fmt.Sprintf("%s: %s", ae.ErrorCode(), ae.ErrorMessage())
	}
	return err.Error()
}

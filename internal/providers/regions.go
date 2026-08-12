// Package providers holds small helper functions for talking to a cloud
// provider's API — right now, just AWS. It deliberately knows NOTHING about
// what a "check" is or what a Result looks like; it only knows how to talk
// to AWS itself. Keeping it this simple means:
//
//  1. internal/checks can safely import this package without any risk of
//     an "import cycle" (where two packages each try to import the other,
//     which Go refuses to compile).
//  2. If ZeroDock ever needs to scan a second cloud provider (say, GCP or
//     Azure), we can add a new file here without touching any check code.
package providers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnabledRegions asks AWS "which regions can this account actually use?"
// and returns their names (like "us-east-1", "eu-west-2", etc.).
//
// Why this matters: AWS has many regions, and some of them are "opt-in"
// regions that are turned OFF by default for new accounts. There's no
// point scanning a region the account can't even use, so we ask AWS
// directly instead of hard-coding a list of region names ourselves (which
// would go stale as AWS adds new regions over time).
func EnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)

	// AllRegions: false means "only regions this account can use", not
	// literally every region AWS has ever created.
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("opt-in-status"),
				Values: []string{"opt-in-not-required", "opted-in"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}

	// The AWS response gives us a list of Region objects; we just want
	// their plain string names.
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	return regions, nil
}

// IntersectRequestedRegions returns the requested regions that AWS says are
// enabled for the account. It preserves the caller's order so the report
// records the exact scope the caller asked for. An empty requested list means
// "all enabled regions", which keeps this helper safe for internal callers
// that have not opted into explicit region scoping.
func IntersectRequestedRegions(requested, enabled []string) []string {
	if len(requested) == 0 {
		return append([]string(nil), enabled...)
	}

	enabledSet := make(map[string]struct{}, len(enabled))
	for _, region := range enabled {
		enabledSet[region] = struct{}{}
	}

	selected := make([]string, 0, len(requested))
	for _, region := range requested {
		if _, ok := enabledSet[region]; ok {
			selected = append(selected, region)
		}
	}
	return selected
}

// UnavailableRequestedRegions returns requested regions that were not in
// AWS's enabled-region response. It is used only for report honesty: a
// caller can see the difference between what was requested and what was
// actually eligible to scan.
func UnavailableRequestedRegions(requested, enabled []string) []string {
	enabledSet := make(map[string]struct{}, len(enabled))
	for _, region := range enabled {
		enabledSet[region] = struct{}{}
	}

	missing := make([]string, 0)
	for _, region := range requested {
		if _, ok := enabledSet[region]; !ok {
			missing = append(missing, region)
		}
	}
	return missing
}

// ForRegion takes an existing AWS config and returns a COPY of it that
// points at a different region. We copy instead of modifying the original
// so that running a check in "us-west-2" can never accidentally affect
// what region a check in "eu-west-1" thinks it's talking to.
func ForRegion(cfg aws.Config, region string) aws.Config {
	regional := cfg.Copy()
	regional.Region = region
	return regional
}

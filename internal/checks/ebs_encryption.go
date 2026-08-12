package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// init() runs automatically the first time this file is loaded, before
// main() even starts. All it does is register this check into the global
// list (checks.All), so cmd/scanner will find and run it without anyone
// having to remember to add it to a list by hand.
func init() {
	Register(Check{
		ID:    "aws.ebs.encryption",
		Title: "Unencrypted EBS volumes",
		Tier:  ProviderAttested,
		Run:   ebsEncryption,
	})
}

// ebsEncryption looks for EBS volumes (AWS's virtual hard disks, attached
// to EC2 servers) that are NOT encrypted. An unencrypted disk means that if
// someone got physical or improper access to the underlying storage, the
// data on it would be readable in plain form.
//
// EBS volumes live inside a specific region, so we use RunAcrossRegions to
// check every region the account has turned on.
func ebsEncryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := ec2.NewFromConfig(regionalCfg)

		var findings []string
		count := 0

		// AWS only sends back a limited number of volumes per API call
		// (a "page"). A paginator is a helper that automatically asks
		// for the next page until there are no more, so we don't have
		// to write that loop-and-fetch-more logic ourselves.
		paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				// Something went wrong (often: missing permission).
				// Bubble the error up instead of pretending we found
				// nothing.
				return nil, 0, err
			}

			for _, vol := range page.Volumes {
				count++

				// vol.Encrypted is a *bool (a pointer), meaning it
				// could technically be nil (missing) instead of just
				// true or false. We treat "missing" the same as
				// "false" — if we're not sure it's encrypted, we
				// don't assume it is.
				if vol.Encrypted == nil || !*vol.Encrypted {
					findings = append(findings, fmt.Sprintf(
						"%s: unencrypted EBS volume %s (%s)",
						regionalCfg.Region,
						aws.ToString(vol.VolumeId),
						string(vol.State),
					))
				}
			}
		}

		return findings, count, nil
	})
}

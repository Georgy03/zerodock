package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

func init() {
	Register(Check{
		ID:    "aws.rds.public_snapshots",
		Title: "Publicly restorable RDS snapshots",
		Tier:  ProviderAttested,
		Run:   rdsPublicSnapshots,
	})
}

// rdsPublicSnapshots looks for RDS database SNAPSHOTS (a saved, point-in-
// time backup/copy of a database) that ANY AWS account in the world could
// restore a copy of. A snapshot contains all the data that was in the
// database at the time it was taken, so a public snapshot is essentially
// the same risk as a public database — except it's easier to miss because
// snapshots aren't as visible as a running database.
//
// This is ProviderAttested even though it takes a second API call per
// snapshot (DescribeDBSnapshotAttributes): that call still just reads a
// fact AWS itself is asserting ("here's who this snapshot is shared
// with"), it isn't us testing anything by actually trying to restore or
// reach the snapshot ourselves.
//
// Two things this check deliberately does NOT do, both for the same
// reason:
//   - It does not pass IncludePublic (which would also list OTHER
//     accounts' snapshots they've shared publicly). DescribeDBSnapshotAttributes
//     only works for snapshots YOUR account owns, so asking it about a
//     snapshot some other account shared with you fails.
//   - It filters to SnapshotType "manual". Only manual snapshots can be
//     shared publicly in the first place, and AWS does not reliably
//     populate DBSnapshotIdentifier for automated snapshots the same way
//     — including them here was producing malformed/empty identifiers
//     that made DescribeDBSnapshotAttributes reject the request.
//
// Both restrictions keep this check to exactly what it can actually
// answer correctly: "of the snapshots THIS account owns and could have
// made public, which ones are public?"
func rdsPublicSnapshots(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := rds.NewFromConfig(regionalCfg)

		var findings []string
		count := 0

		paginator := rds.NewDescribeDBSnapshotsPaginator(client, &rds.DescribeDBSnapshotsInput{
			SnapshotType: aws.String("manual"),
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}

			for _, snap := range page.DBSnapshots {
				count++

				// DescribeDBSnapshotAttributes wants the BARE
				// identifier (e.g. "my-snapshot-2024-01-01"), not the
				// full ARN (e.g. "arn:aws:rds:...:snapshot:my-snapshot-...").
				// snap.DBSnapshotIdentifier is already the bare form —
				// snap.DBSnapshotArn is the separate, full-ARN field we
				// must NOT pass here.
				attrOut, err := client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
					DBSnapshotIdentifier: snap.DBSnapshotIdentifier,
				})
				if err != nil {
					return nil, 0, err
				}

				if snapshotAttributesArePublic(attrOut.DBSnapshotAttributesResult) {
					findings = append(findings, fmt.Sprintf(
						"%s: publicly restorable RDS snapshot %s (source %s)",
						regionalCfg.Region,
						aws.ToString(snap.DBSnapshotIdentifier),
						aws.ToString(snap.DBInstanceIdentifier),
					))
				}
			}
		}

		return findings, count, nil
	})
}

// snapshotAttributesArePublic looks inside the "who can restore this
// snapshot" answer from AWS and decides whether the special value "all"
// (meaning literally every AWS account, i.e. the whole public internet) is
// present. AWS represents this as a list of named attributes; the one we
// care about is named "restore", and its list of values is either specific
// AWS account IDs (private sharing) or the single word "all" (public).
func snapshotAttributesArePublic(result *rdstypes.DBSnapshotAttributesResult) bool {
	if result == nil {
		return false
	}

	for _, attr := range result.DBSnapshotAttributes {
		// We only care about the "restore" attribute — there can be
		// other, unrelated attributes in this list.
		if aws.ToString(attr.AttributeName) != "restore" {
			continue
		}

		for _, v := range attr.AttributeValues {
			if v == "all" {
				return true
			}
		}
	}

	return false
}

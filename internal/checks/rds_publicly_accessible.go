package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

func init() {
	Register(Check{
		ID:    "aws.rds.publicly_accessible",
		Title: "Publicly accessible RDS instances",
		Tier:  ProviderAttested,
		Run:   rdsPubliclyAccessible,
	})
}

// rdsPubliclyAccessible looks for RDS databases that AWS has marked with
// "PubliclyAccessible: true". That setting means the database has been
// given a public IP address and can potentially be reached directly from
// the internet, instead of only from inside your own private network
// (VPC). Databases usually should NOT be publicly accessible — attackers
// scan the internet constantly looking for exposed databases to break
// into.
func rdsPubliclyAccessible(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := rds.NewFromConfig(regionalCfg)

		var findings []string
		count := 0

		paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}

			for _, db := range page.DBInstances {
				count++

				// Here we DO want the "missing means false" default
				// to behave the opposite way from the encryption
				// checks: we only flag it if PubliclyAccessible is
				// explicitly true. A nil/missing value means "not
				// public", which is the safe assumption here.
				if db.PubliclyAccessible != nil && *db.PubliclyAccessible {
					findings = append(findings, fmt.Sprintf(
						"%s: publicly accessible RDS instance %s (%s)",
						regionalCfg.Region,
						aws.ToString(db.DBInstanceIdentifier),
						aws.ToString(db.Engine),
					))
				}
			}
		}

		return findings, count, nil
	})
}

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
		ID:    "aws.rds.encryption",
		Title: "RDS instances without storage encryption",
		Tier:  ProviderAttested,
		Run:   rdsEncryption,
	})
}

// rdsEncryption looks for RDS databases (AWS's managed database service —
// think MySQL, PostgreSQL, etc. that AWS runs and maintains for you) whose
// underlying storage is NOT encrypted. Just like an unencrypted hard disk,
// an unencrypted database's raw storage could expose data if someone got
// access to it outside of the normal database login.
func rdsEncryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := rds.NewFromConfig(regionalCfg)

		var findings []string
		count := 0

		// Same pagination pattern as the EBS check: keep asking AWS
		// for the next batch of database instances until there isn't
		// one.
		paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}

			for _, db := range page.DBInstances {
				count++

				// StorageEncrypted is another *bool. If it's missing
				// or false, treat the database as unencrypted.
				if db.StorageEncrypted == nil || !*db.StorageEncrypted {
					findings = append(findings, fmt.Sprintf(
						"%s: unencrypted RDS instance %s (%s)",
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

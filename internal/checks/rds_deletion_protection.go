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
		ID:    "aws.rds.deletion_protection",
		Title: "RDS instances without deletion protection",
		Tier:  ProviderAttested,
		Run:   rdsDeletionProtection,
	})
}

// rdsDeletionProtection looks for RDS databases that do NOT have "deletion
// protection" turned on. Deletion protection is a simple AWS safety switch
// that stops a database from being deleted by accident (either by a
// person clicking the wrong button, or by a misconfigured/buggy automation
// script). It costs nothing and has no downside, so any production
// database missing it is worth flagging.
func rdsDeletionProtection(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
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

				if db.DeletionProtection == nil || !*db.DeletionProtection {
					findings = append(findings, fmt.Sprintf(
						"%s: RDS instance %s does not have deletion protection enabled",
						regionalCfg.Region,
						aws.ToString(db.DBInstanceIdentifier),
					))
				}
			}
		}

		return findings, count, nil
	})
}

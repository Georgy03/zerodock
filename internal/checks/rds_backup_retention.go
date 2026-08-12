package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// minBackupRetentionDays is our security policy: any database keeping
// fewer than this many days of automatic backups is flagged. 7 days gives
// a reasonable window to notice and recover from data loss, ransomware, or
// an accidental "oops I deleted the wrong table" moment.
const minBackupRetentionDays = 7

func init() {
	Register(Check{
		ID:    "aws.rds.backup_retention",
		Title: "RDS instances with backup retention under 7 days",
		Tier:  ProviderAttested,
		Run:   rdsBackupRetention,
	})
}

// rdsBackupRetention checks how many days of automatic backups each RDS
// database is configured to keep, and flags any that keep fewer than
// minBackupRetentionDays. A database with backups turned off entirely
// (retention = 0) is the worst case and will also be flagged here.
func rdsBackupRetention(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
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

				// BackupRetentionPeriod is a *int32 (a pointer to a
				// number). If AWS didn't send us a value at all, we
				// treat that the same as "0 days" — the safest
				// assumption, since we'd rather over-report a
				// possible problem than miss a real one.
				retention := int32(0)
				if db.BackupRetentionPeriod != nil {
					retention = *db.BackupRetentionPeriod
				}

				if retention < minBackupRetentionDays {
					findings = append(findings, fmt.Sprintf(
						"%s: RDS instance %s has backup retention of %d day(s), below the %d-day minimum",
						regionalCfg.Region,
						aws.ToString(db.DBInstanceIdentifier),
						retention,
						minBackupRetentionDays,
					))
				}
			}
		}

		return findings, count, nil
	})
}

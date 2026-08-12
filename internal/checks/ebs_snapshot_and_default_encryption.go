package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func init() {
	Register(Check{ID: "aws.ebs.snapshot_encryption", Title: "Unencrypted account-owned EBS snapshots", Tier: ProviderAttested, Run: ebsSnapshotEncryption})
	Register(Check{ID: "aws.ebs.default_encryption", Title: "EBS encryption by default disabled", Tier: ProviderAttested, Run: ebsDefaultEncryption})
}

func ebsSnapshotEncryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := ec2.NewFromConfig(regionalCfg)
		var findings []string
		count := 0
		paginator := ec2.NewDescribeSnapshotsPaginator(client, &ec2.DescribeSnapshotsInput{OwnerIds: []string{"self"}})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, 0, err
			}
			for _, snapshot := range page.Snapshots {
				count++
				if snapshot.Encrypted == nil || !*snapshot.Encrypted {
					findings = append(findings, fmt.Sprintf("%s: EBS snapshot %s is not encrypted", regionalCfg.Region, aws.ToString(snapshot.SnapshotId)))
				}
			}
		}
		return findings, count, nil
	})
}

func ebsDefaultEncryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := ec2.NewFromConfig(regionalCfg)
		out, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
		if err != nil {
			return nil, 0, err
		}
		if !aws.ToBool(out.EbsEncryptionByDefault) {
			return []string{fmt.Sprintf("%s: EBS encryption by default is disabled", regionalCfg.Region)}, 1, nil
		}
		return nil, 1, nil
	})
}

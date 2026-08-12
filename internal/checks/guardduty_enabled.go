package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

func init() {
	Register(Check{ID: "aws.guardduty.enabled", Title: "GuardDuty absent or suspended", Tier: ProviderAttested, Run: guardDutyEnabled})
}

func guardDutyEnabled(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return RunAcrossRegions(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, int, error) {
		client := guardduty.NewFromConfig(regionalCfg)
		out, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
		if err != nil {
			return nil, 0, err
		}
		if len(out.DetectorIds) == 0 {
			return []string{fmt.Sprintf("%s: GuardDuty has no detector", regionalCfg.Region)}, 0, nil
		}

		var findings []string
		for _, detectorID := range out.DetectorIds {
			detector, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: aws.String(detectorID)})
			if err != nil {
				return nil, 0, fmt.Errorf("get GuardDuty detector %s: %w", detectorID, err)
			}
			if detector.Status != types.DetectorStatusEnabled {
				findings = append(findings, fmt.Sprintf("%s: GuardDuty detector %s is %s", regionalCfg.Region, detectorID, detector.Status))
			}
		}
		return findings, len(out.DetectorIds), nil
	})
}

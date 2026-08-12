package checks

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
)

func init() {
	Register(Check{
		ID:    "aws.cloudtrail.multiregion",
		Title: "No active multi-region CloudTrail trail",
		Tier:  ProviderAttested,
		Run:   cloudtrailMultiregion,
	})
}

// CloudTrail is AWS's activity logging service — it records who did what
// in your account (e.g. "user Bob deleted this S3 bucket at 3:14pm"). A
// "trail" is a specific logging configuration. This check makes sure at
// least one MULTI-REGION trail exists and is actively logging.
//
// Why "multi-region" specifically matters: if you only log activity in
// one region, an attacker (or an accidental mistake) in a DIFFERENT region
// would go completely unrecorded. A multi-region trail automatically
// covers every region, including ones you don't normally use — so there's
// no blind spot.
//
// This is a GLOBAL check, not a per-region one — even though it's checking
// something about "every region", CloudTrail's API is smart about this:
// when you ask about trails from any single region, it automatically
// includes "shadow" copies (replicas) of every multi-region trail,
// regardless of which region it was originally created in. So calling this
// once already sees everything; looping over every region would just show
// us the same multi-region trails over and over.
func cloudtrailMultiregion(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	client := cloudtrail.NewFromConfig(cfg)

	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
	}

	// First, find every trail that's configured as multi-region.
	var multiRegionTrails []string
	for _, trail := range out.TrailList {
		if trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail {
			multiRegionTrails = append(multiRegionTrails, aws.ToString(trail.TrailARN))
		}
	}

	// If there isn't even one multi-region trail, that's an immediate
	// fail — there's nothing left to check.
	if len(multiRegionTrails) == 0 {
		return Result{
			Status:   StatusFail,
			Findings: []string{"no multi-region CloudTrail trail exists in this account"},
			Count:    len(out.TrailList),
		}, nil
	}

	// A trail can exist but still have its logging turned OFF (someone
	// paused it). So for each multi-region trail we found, double-check
	// that it's actually, currently logging.
	var findings []string
	activeCount := 0
	for _, arn := range multiRegionTrails {
		statusOut, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(arn)})
		if err != nil {
			return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
		}

		if statusOut.IsLogging == nil || !*statusOut.IsLogging {
			findings = append(findings, "multi-region trail "+arn+" exists but logging is stopped")
			continue
		}

		activeCount++
	}

	// We pass as long as AT LEAST ONE multi-region trail is actively
	// logging — having others that are stopped is worth noting as a
	// finding, but doesn't make the whole account unprotected.
	status := StatusPass
	if activeCount == 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: len(out.TrailList)}, nil
}

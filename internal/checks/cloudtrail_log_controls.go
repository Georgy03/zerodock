package checks

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	Register(Check{ID: "aws.cloudtrail.log_encryption", Title: "CloudTrail logs without KMS and S3 encryption", Tier: ProviderAttested, Run: cloudTrailLogEncryption})
	Register(Check{ID: "aws.cloudtrail.log_validation", Title: "CloudTrail log-file validation disabled", Tier: ProviderAttested, Run: cloudTrailLogValidation})
}

// distinctTrails removes shadow/duplicate descriptions by ARN. DescribeTrails
// can return a multi-region trail through more than one regional view, but a
// control result should count and report the underlying trail once.
func distinctTrails(trails []types.Trail) []types.Trail {
	seen := make(map[string]bool)
	out := make([]types.Trail, 0, len(trails))
	for _, trail := range trails {
		identity := aws.ToString(trail.TrailARN)
		if identity == "" {
			identity = aws.ToString(trail.Name)
		}
		if identity == "" || seen[identity] {
			continue
		}
		seen[identity] = true
		out = append(out, trail)
	}
	sort.Slice(out, func(i, j int) bool { return trailName(out[i]) < trailName(out[j]) })
	return out
}

func trailName(trail types.Trail) string {
	if arn := aws.ToString(trail.TrailARN); arn != "" {
		return arn
	}
	return aws.ToString(trail.Name)
}

func cloudTrailLogValidation(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	client := cloudtrail.NewFromConfig(cfg)
	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
	}
	trails := distinctTrails(out.TrailList)
	if len(trails) == 0 {
		return Result{Status: StatusFail, Findings: []string{"no CloudTrail trails exist to protect with log-file validation"}}, nil
	}
	var findings []string
	for _, trail := range trails {
		if !aws.ToBool(trail.LogFileValidationEnabled) {
			findings = append(findings, "CloudTrail trail "+trailName(trail)+" has log-file validation disabled")
		}
	}
	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: len(trails)}, nil
}

func cloudTrailLogEncryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	trailClient := cloudtrail.NewFromConfig(cfg)
	out, err := trailClient.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
	}
	trails := distinctTrails(out.TrailList)
	if len(trails) == 0 {
		return Result{Status: StatusFail, Findings: []string{"no CloudTrail trails exist to encrypt"}}, nil
	}
	locationClient := s3.NewFromConfig(cfg)
	var findings, errs []string
	bucketEncrypted := make(map[string]bool)
	bucketChecked := make(map[string]bool)
	bucketReadable := make(map[string]bool)
	for _, trail := range trails {
		name := trailName(trail)
		if aws.ToString(trail.KmsKeyId) == "" {
			findings = append(findings, "CloudTrail trail "+name+" does not use a KMS key")
		}
		bucket := aws.ToString(trail.S3BucketName)
		if bucket == "" {
			findings = append(findings, "CloudTrail trail "+name+" has no S3 destination bucket")
			continue
		}
		if !bucketChecked[bucket] {
			bucketChecked[bucket] = true
			region, err := bucketRegion(ctx, locationClient, bucket)
			if err != nil {
				errs = append(errs, fmt.Sprintf("CloudTrail bucket %s: get location: %s", bucket, describeErr(err)))
			} else {
				regionalClient := s3.NewFromConfig(cfg, func(options *s3.Options) { options.Region = region })
				_, err = regionalClient.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)})
				switch {
				case err == nil:
					bucketReadable[bucket] = true
					bucketEncrypted[bucket] = true
				case isNoSuchConfig(err):
					bucketReadable[bucket] = true
				default:
					errs = append(errs, fmt.Sprintf("CloudTrail bucket %s: get encryption: %s", bucket, describeErr(err)))
				}
			}
		}
		if bucketReadable[bucket] && !bucketEncrypted[bucket] {
			findings = append(findings, fmt.Sprintf("CloudTrail trail %s writes to S3 bucket %s without default encryption", name, bucket))
		}
	}
	if len(errs) > 0 {
		return Result{Status: StatusError, Findings: append(findings, errs...), Count: len(trails)}, nil
	}
	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: len(trails)}, nil
}

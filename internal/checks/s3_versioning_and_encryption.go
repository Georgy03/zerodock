package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func init() {
	Register(Check{ID: "aws.s3.versioning", Title: "S3 buckets without versioning", Tier: ProviderAttested, Run: s3Versioning})
	Register(Check{ID: "aws.s3.encryption", Title: "S3 buckets without default encryption", Tier: ProviderAttested, Run: s3Encryption})
}

type s3BucketInspector func(context.Context, *s3.Client, string, string) (string, error)

func scanS3Buckets(ctx context.Context, cfg aws.Config, inspect s3BucketInspector) (Result, error) {
	listClient := s3.NewFromConfig(cfg)
	listed, err := listClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{"list buckets: " + describeErr(err)}}, nil
	}
	var findings, errs []string
	for _, bucket := range listed.Buckets {
		name := aws.ToString(bucket.Name)
		region, err := bucketRegion(ctx, listClient, name)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: get bucket location: %s", name, describeErr(err)))
			continue
		}
		regionalClient := s3.NewFromConfig(cfg, func(options *s3.Options) { options.Region = region })
		finding, err := inspect(ctx, regionalClient, region, name)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", name, describeErr(err)))
			continue
		}
		if finding != "" {
			findings = append(findings, finding)
		}
	}
	if len(errs) > 0 {
		return Result{Status: StatusError, Findings: append(findings, errs...), Count: len(listed.Buckets)}, nil
	}
	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: len(listed.Buckets)}, nil
}

func s3Versioning(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return scanS3Buckets(ctx, cfg, func(ctx context.Context, client *s3.Client, region, bucket string) (string, error) {
		out, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
		if err != nil {
			return "", err
		}
		if out.Status != s3types.BucketVersioningStatusEnabled {
			return fmt.Sprintf("%s: S3 bucket %s does not have versioning enabled", region, bucket), nil
		}
		return "", nil
	})
}

func s3Encryption(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	return scanS3Buckets(ctx, cfg, func(ctx context.Context, client *s3.Client, region, bucket string) (string, error) {
		_, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)})
		if err != nil {
			if isNoSuchConfig(err) {
				return fmt.Sprintf("%s: S3 bucket %s has no default encryption configuration", region, bucket), nil
			}
			return "", err
		}
		return "", nil
	})
}

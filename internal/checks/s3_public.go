package checks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

func init() {
	Register(Check{
		ID:    "aws.s3.public",
		Title: "S3 buckets exposed to public access",
		Tier:  ProviderAttested,
		Run:   s3Public,
	})
}

// s3Public looks for S3 buckets (AWS's file/object storage service — think
// of it like a giant, simple hard drive in the cloud) that the public
// internet could read from or write to. A misconfigured "public" bucket is
// one of the most common real-world AWS data leaks — people accidentally
// expose customer data, backups, or source code this way all the time.
//
// This is ProviderAttested, not ActivelyProbed: even though we combine two
// separate API calls to reach a conclusion, both calls are AWS reporting
// its own computed state (the public access block config, and its own
// "is this policy public" verdict from GetBucketPolicyStatus) — we never
// actually try to reach the bucket over the network ourselves.
//
// This check is NOT looped by region like the EC2/RDS checks above.
// That's because listing S3 buckets is an account-wide operation — it
// doesn't matter which region you ask from, you get every bucket in the
// account back at once. Instead, each bucket has its OWN region (wherever
// it was created), and we have to build a client pointed at that specific
// bucket's region before we can ask detailed questions about it — S3
// rejects detailed requests sent to the wrong region.
func s3Public(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	listClient := s3.NewFromConfig(cfg)

	listOut, err := listClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{fmt.Sprintf("list buckets: %s", describeErr(err))}}, nil
	}

	var findings []string
	var errs []string
	count := 0

	for _, bucket := range listOut.Buckets {
		name := aws.ToString(bucket.Name)
		count++

		// Step 1: find out which region this particular bucket
		// actually lives in.
		region, err := bucketRegion(ctx, listClient, name)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: get bucket location: %s", name, describeErr(err)))
			continue
		}

		// Step 2: build a fresh S3 client pointed specifically at that
		// region, so the next calls succeed.
		regionalClient := s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.Region = region
		})

		// Step 3: actually decide if the bucket is public.
		public, reason, err := bucketIsPublic(ctx, regionalClient, name)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", name, describeErr(err)))
			continue
		}
		if public {
			findings = append(findings, fmt.Sprintf("%s: bucket %s is publicly accessible (%s)", region, name, reason))
		}
	}

	// Same rule as everywhere else: any error becomes an "error" status,
	// never a silently-skipped bucket.
	if len(errs) > 0 {
		return Result{Status: StatusError, Findings: append(findings, errs...), Count: count}, nil
	}

	status := StatusPass
	if len(findings) > 0 {
		status = StatusFail
	}
	return Result{Status: status, Findings: findings, Count: count}, nil
}

// bucketRegion asks AWS which region a specific bucket lives in.
func bucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	out, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket)})
	if err != nil {
		return "", err
	}

	region := string(out.LocationConstraint)

	// Quirk of the S3 API: buckets in the original "us-east-1" region
	// report back an EMPTY location instead of the name "us-east-1".
	if region == "" {
		region = "us-east-1"
	}
	// Older quirk: some very old buckets report the region as literally
	// "EU" instead of a real region name.
	if region == "EU" {
		region = "eu-west-1"
	}

	return region, nil
}

// bucketIsPublic decides whether a bucket can be reached by the public
// internet. There are two independent ways this can happen in S3, and we
// check both:
//
//  1. "Public Access Block" — a bucket-level safety switch with four
//     separate toggles. If ANY of the four aren't fully turned on, the
//     bucket could be exposed.
//  2. If there's no Public Access Block at all, we fall back to asking S3
//     directly whether the bucket's attached POLICY (a set of permission
//     rules) makes it public. AWS actually computes this "is it public"
//     answer for us via GetBucketPolicyStatus, so we don't have to parse
//     the policy's rules ourselves.
func bucketIsPublic(ctx context.Context, client *s3.Client, bucket string) (bool, string, error) {
	pabOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})

	// It's completely normal (not an error we care about) for a bucket
	// to have NO Public Access Block configuration at all. isNoSuchConfig
	// recognizes that specific "not configured" error and lets us treat
	// it as "no config found" rather than a real failure.
	if err != nil && !isNoSuchConfig(err) {
		return false, "", err
	}

	if err == nil && pabOut.PublicAccessBlockConfiguration != nil {
		cfg := pabOut.PublicAccessBlockConfiguration

		// All four settings need to be true for the bucket to be
		// FULLY locked down. If even one is false, something could
		// still leak through.
		fullyBlocked := aws.ToBool(cfg.BlockPublicAcls) &&
			aws.ToBool(cfg.BlockPublicPolicy) &&
			aws.ToBool(cfg.IgnorePublicAcls) &&
			aws.ToBool(cfg.RestrictPublicBuckets)

		if !fullyBlocked {
			return true, "public access block does not block all public access", nil
		}
		// Public Access Block is fully on — this bucket is safe from
		// public policies, so we're done; no need to check the
		// bucket policy separately.
		return false, "", nil
	}

	// No Public Access Block configured at all — check the bucket's
	// policy instead.
	policyOut, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(bucket)})
	if err != nil {
		if isNoSuchConfig(err) {
			// No Public Access Block AND no policy at all: this
			// check can't say it's public. (Note: it could still be
			// exposed through old-style ACLs, which this particular
			// AWS API call doesn't cover — that's a known limit of
			// this check, not a bug.)
			return false, "", nil
		}
		return false, "", err
	}

	if policyOut.PolicyStatus != nil && aws.ToBool(policyOut.PolicyStatus.IsPublic) {
		return true, "no public access block and bucket policy is public", nil
	}

	return false, "", nil
}

// isNoSuchConfig recognizes the specific "this bucket doesn't have that
// configuration at all" errors S3 returns. These aren't real failures —
// they just mean "nothing set here", which is a completely normal bucket
// state we need to handle, not something to report as an error.
func isNoSuchConfig(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		code := ae.ErrorCode()
		return code == "NoSuchPublicAccessBlockConfiguration" || code == "NoSuchBucketPolicy" || code == "NoSuchLifecycleConfiguration" || code == "ServerSideEncryptionConfigurationNotFoundError"
	}
	return false
}

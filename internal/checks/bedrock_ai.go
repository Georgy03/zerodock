package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cloudwatchlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	Register(Check{ID: "aws.bedrock.invocation_logging", Title: "Bedrock model invocation logging and destination protection", Tier: ProviderAttested, Run: bedrockInvocationLogging})
	Register(Check{ID: "aws.bedrock.guardrails", Title: "Bedrock guardrail readiness", Tier: ProviderAttested, Run: bedrockGuardrails})
	Register(Check{ID: "aws.bedrock.model_access", Title: "Bedrock third-party model agreement inventory", Tier: ProviderAttested, Run: bedrockModelAccess})
	Register(Check{ID: "aws.bedrock.customization_jobs", Title: "Bedrock model customization and training-data inventory", Tier: ProviderAttested, Run: bedrockCustomizationJobs})
}

func bedrockInvocationLogging(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	return RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrock.NewFromConfig(regionalCfg)
		out, err := client.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
		if err != nil {
			return nil, nil, 0, err
		}
		if out.LoggingConfig == nil || !bedrockLoggingEnabled(out.LoggingConfig) {
			return []string{fmt.Sprintf("%s: Bedrock model invocation logging is disabled; actual model usage cannot be ruled out", regionalCfg.Region)}, nil, 1, nil
		}

		config := out.LoggingConfig
		var findings, evidence []string
		destinations := 0
		if config.S3Config != nil {
			destinations++
			bucketFindings, bucketEvidence, err := inspectBedrockLoggingBucket(ctx, regionalCfg, config.S3Config, "S3")
			if err != nil {
				return findings, evidence, 1, err
			}
			findings, evidence = append(findings, bucketFindings...), append(evidence, bucketEvidence...)
		}
		if config.CloudWatchConfig != nil {
			destinations++
			groupFindings, groupEvidence, err := inspectBedrockLogGroup(ctx, regionalCfg, aws.ToString(config.CloudWatchConfig.LogGroupName))
			if err != nil {
				return findings, evidence, 1, err
			}
			findings, evidence = append(findings, groupFindings...), append(evidence, groupEvidence...)
			if config.CloudWatchConfig.LargeDataDeliveryS3Config != nil {
				destinations++
				bucketFindings, bucketEvidence, err := inspectBedrockLoggingBucket(ctx, regionalCfg, config.CloudWatchConfig.LargeDataDeliveryS3Config, "CloudWatch large-data S3")
				if err != nil {
					return findings, evidence, 1, err
				}
				findings, evidence = append(findings, bucketFindings...), append(evidence, bucketEvidence...)
			}
		}
		if destinations == 0 {
			findings = append(findings, fmt.Sprintf("%s: Bedrock invocation logging is enabled but has no S3 or CloudWatch destination", regionalCfg.Region))
		}
		return findings, evidence, 1, nil
	})
}

func bedrockLoggingEnabled(config *bedrocktypes.LoggingConfig) bool {
	return aws.ToBool(config.TextDataDeliveryEnabled) || aws.ToBool(config.ImageDataDeliveryEnabled) ||
		aws.ToBool(config.EmbeddingDataDeliveryEnabled) || aws.ToBool(config.VideoDataDeliveryEnabled) ||
		aws.ToBool(config.AudioDataDeliveryEnabled)
}

func inspectBedrockLoggingBucket(ctx context.Context, cfg aws.Config, destination *bedrocktypes.S3Config, label string) ([]string, []string, error) {
	name := aws.ToString(destination.BucketName)
	if name == "" {
		return []string{fmt.Sprintf("%s: Bedrock %s logging destination has no bucket name", cfg.Region, label)}, nil, nil
	}
	listClient := s3.NewFromConfig(cfg)
	region, err := bucketRegion(ctx, listClient, name)
	if err != nil {
		return nil, nil, fmt.Errorf("Bedrock log bucket %s location: %w", name, err)
	}
	client := s3.NewFromConfig(cfg, func(options *s3.Options) { options.Region = region })
	var findings []string
	if _, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(name)}); err != nil {
		if isNoSuchConfig(err) {
			findings = append(findings, fmt.Sprintf("%s: Bedrock %s log bucket %s has no default encryption configuration", cfg.Region, label, name))
		} else {
			return nil, nil, fmt.Errorf("Bedrock log bucket %s encryption: %w", name, err)
		}
	}
	public, reason, err := bucketIsPublic(ctx, client, name)
	if err != nil {
		return nil, nil, fmt.Errorf("Bedrock log bucket %s public access: %w", name, err)
	}
	if public {
		findings = append(findings, fmt.Sprintf("%s: Bedrock %s log bucket %s is publicly accessible (%s)", cfg.Region, label, name, reason))
	}
	acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(name)})
	if err != nil {
		return nil, nil, fmt.Errorf("Bedrock log bucket %s ACL: %w", name, err)
	}
	for _, grant := range acl.Grants {
		if grant.Grantee == nil {
			continue
		}
		uri := aws.ToString(grant.Grantee.URI)
		if uri == "http://acs.amazonaws.com/groups/global/AllUsers" || uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
			findings = append(findings, fmt.Sprintf("%s: Bedrock %s log bucket %s has a public ACL grant (%s)", cfg.Region, label, name, grant.Permission))
		}
	}
	evidence := []string{fmt.Sprintf("%s: Bedrock %s invocation logs use s3://%s/%s", cfg.Region, label, name, aws.ToString(destination.KeyPrefix))}
	return findings, evidence, nil
}

func inspectBedrockLogGroup(ctx context.Context, cfg aws.Config, name string) ([]string, []string, error) {
	if name == "" {
		return []string{fmt.Sprintf("%s: Bedrock CloudWatch logging destination has no log group name", cfg.Region)}, nil, nil
	}
	client := cloudwatchlogs.NewFromConfig(cfg)
	out, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{LogGroupIdentifiers: []string{name}})
	if err != nil {
		return nil, nil, fmt.Errorf("describe Bedrock log group %s: %w", name, err)
	}
	var kmsKey, arn string
	for _, group := range out.LogGroups {
		if aws.ToString(group.LogGroupName) == name {
			kmsKey, arn = aws.ToString(group.KmsKeyId), aws.ToString(group.Arn)
			break
		}
	}
	if arn == "" {
		return []string{fmt.Sprintf("%s: Bedrock invocation log group %s does not exist", cfg.Region, name)}, nil, nil
	}
	var findings []string
	if kmsKey == "" {
		findings = append(findings, fmt.Sprintf("%s: Bedrock invocation log group %s is not encrypted with a customer KMS key", cfg.Region, name))
	}
	policies, err := describeCloudWatchResourcePolicies(ctx, client, arn)
	if err != nil {
		return nil, nil, fmt.Errorf("describe CloudWatch Logs resource policies: %w", err)
	}
	for _, policy := range policies {
		if policyAllowsUnrestrictedPublic(aws.ToString(policy.PolicyDocument), arn) {
			findings = append(findings, fmt.Sprintf("%s: CloudWatch Logs resource policy %s permits an unrestricted public principal and may expose Bedrock prompts", cfg.Region, aws.ToString(policy.PolicyName)))
		}
	}
	return findings, []string{fmt.Sprintf("%s: Bedrock invocation logs use encrypted CloudWatch log group %s", cfg.Region, name)}, nil
}

func describeCloudWatchResourcePolicies(ctx context.Context, client *cloudwatchlogs.Client, resourceARN string) ([]cloudwatchlogstypes.ResourcePolicy, error) {
	var policies []cloudwatchlogstypes.ResourcePolicy
	for _, input := range []*cloudwatchlogs.DescribeResourcePoliciesInput{
		{},
		{PolicyScope: cloudwatchlogstypes.PolicyScopeResource, ResourceArn: aws.String(resourceARN)},
	} {
		for {
			page, err := client.DescribeResourcePolicies(ctx, input)
			if err != nil {
				return nil, err
			}
			policies = append(policies, page.ResourcePolicies...)
			if aws.ToString(page.NextToken) == "" {
				break
			}
			input.NextToken = page.NextToken
		}
	}
	return policies, nil
}

// policyAllowsUnrestrictedPublic deliberately flags only an unconditional
// Allow with Principal "*". Conditional service-delivery policies are common
// for CloudWatch Logs and must not be mislabeled as public.
func policyAllowsUnrestrictedPublic(document, targetARN string) bool {
	var policy struct {
		Statement []map[string]any `json:"Statement"`
	}
	if json.Unmarshal([]byte(document), &policy) != nil {
		return false
	}
	for _, statement := range policy.Statement {
		if statement["Effect"] != "Allow" || statement["Condition"] != nil {
			continue
		}
		principal := statement["Principal"]
		publicPrincipal := principal == "*"
		if values, ok := principal.(map[string]any); ok {
			publicPrincipal = values["AWS"] == "*"
		}
		if publicPrincipal && policyResourceMatches(statement["Resource"], targetARN) {
			return true
		}
	}
	return false
}

func policyResourceMatches(raw any, targetARN string) bool {
	matches := func(resource string) bool {
		if resource == "*" || resource == targetARN {
			return true
		}
		return len(resource) > 1 && resource[len(resource)-1] == '*' && len(targetARN) >= len(resource)-1 && targetARN[:len(resource)-1] == resource[:len(resource)-1]
	}
	switch resources := raw.(type) {
	case string:
		return matches(resources)
	case []any:
		for _, resource := range resources {
			if value, ok := resource.(string); ok && matches(value) {
				return true
			}
		}
	}
	return false
}

func bedrockGuardrails(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrock.NewFromConfig(regionalCfg)
		paginator := bedrock.NewListGuardrailsPaginator(client, &bedrock.ListGuardrailsInput{})
		var guardrails []bedrocktypes.GuardrailSummary
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, nil, len(guardrails), err
			}
			guardrails = append(guardrails, page.Guardrails...)
		}
		if len(guardrails) == 0 {
			logging, err := client.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
			if err != nil {
				return nil, nil, 0, err
			}
			if logging.LoggingConfig != nil && bedrockLoggingEnabled(logging.LoggingConfig) {
				// Someone had to explicitly turn logging on — that's a real
				// signal Bedrock is in active use, and no guardrails
				// alongside that signal is a genuine finding worth flagging.
				return []string{fmt.Sprintf("%s: Bedrock invocation logging is enabled but no guardrails are configured", regionalCfg.Region)}, nil, 0, nil
			}
			// No guardrails AND no logging signal: nothing here looks like
			// active Bedrock usage, so report this region clean rather than
			// manufacturing an evidence line that reads like a problem
			// ("guardrails absent, logging disabled") sitting right next to
			// a summary that says "no applicable resources" — those two
			// statements read as contradictory even though neither is
			// technically wrong. The "logging disabled means ad-hoc calls
			// can't be ruled out" caveat already belongs to, and is already
			// surfaced by, aws.bedrock.invocation_logging; repeating it here
			// only duplicates it under a status that says the opposite.
			return nil, nil, 0, nil
		}
		var findings, evidence []string
		for _, guardrail := range guardrails {
			name, status := aws.ToString(guardrail.Name), guardrail.Status
			evidence = append(evidence, fmt.Sprintf("%s: Bedrock guardrail %s is %s", regionalCfg.Region, name, status))
			if status != bedrocktypes.GuardrailStatusReady {
				findings = append(findings, fmt.Sprintf("%s: Bedrock guardrail %s is %s, not READY", regionalCfg.Region, name, status))
			}
		}
		return findings, evidence, len(guardrails), nil
	})
	return MarkNotInUse(result, "no Bedrock guardrails were found in the scanned regions"), err
}

func bedrockModelAccess(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrock.NewFromConfig(regionalCfg)
		models, err := client.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
		if err != nil {
			return nil, nil, 0, err
		}
		// ListFoundationModels is only the catalog used to discover model IDs.
		// It is not account-specific and must never be returned as inventory.
		// GetFoundationModelAvailability adds the account-specific agreement
		// state. An AVAILABLE agreement normally means the account accepted a
		// third-party Marketplace agreement (often on first invocation), but is
		// still not proof that the model is currently used.
		agreements := make(map[string]string)
		for _, model := range models.ModelSummaries {
			availability, err := client.GetFoundationModelAvailability(ctx, &bedrock.GetFoundationModelAvailabilityInput{ModelId: model.ModelId})
			if err != nil {
				return nil, nil, len(agreements), fmt.Errorf("get availability for model %s: %w", aws.ToString(model.ModelId), err)
			}
			provider := aws.ToString(model.ProviderName)
			if hasAccountSpecificThirdPartyAgreement(provider, availability.AgreementAvailability) {
				// The catalog can contain aliases for the same agreement. AWS returns
				// the canonical model ID from the availability call, so key by that
				// value instead of repeating every catalog alias.
				modelID := aws.ToString(availability.ModelId)
				if modelID == "" {
					modelID = aws.ToString(model.ModelId)
				}
				agreements[modelID] = fmt.Sprintf("%s: active agreement for %s (%s)", regionalCfg.Region, modelID, provider)
			}
		}
		evidence := make([]string, 0, len(agreements))
		for _, agreement := range agreements {
			evidence = append(evidence, agreement)
		}
		sort.Strings(evidence)
		if len(evidence) == 0 {
			return nil, []string{fmt.Sprintf("%s: no active third-party Bedrock model agreements found; this does not rule out first-party or unlogged model calls", regionalCfg.Region)}, 0, nil
		}
		return nil, evidence, len(evidence), nil
	})
	if err == nil && result.Status == StatusPass && result.Count == 0 {
		result.Status = StatusNotInUse
	}
	return result, err
}

func hasAccountSpecificThirdPartyAgreement(provider string, agreement *bedrocktypes.AgreementAvailability) bool {
	// Amazon models are first-party and enabled by default. Their API response
	// can still say agreementAvailability=AVAILABLE, but that is not evidence
	// that this account requested or accepted third-party model access.
	return !strings.EqualFold(strings.TrimSpace(provider), "Amazon") &&
		agreement != nil && agreement.Status == bedrocktypes.AgreementStatusAvailable
}

func bedrockCustomizationJobs(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrock.NewFromConfig(regionalCfg)
		paginator := bedrock.NewListModelCustomizationJobsPaginator(client, &bedrock.ListModelCustomizationJobsInput{})
		var evidence []string
		count := 0
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				// Bedrock is available in more regions than model fine-tuning.
				// In a Bedrock region where this specific control-plane API is
				// unavailable, AWS returns UnknownOperationException. That proves
				// customization jobs cannot be listed or created through this API
				// in the region; it is a signed not-applicable fact, not a missing
				// permission. Every other error remains an error.
				if isAWSAPIErrorCode(err, "UnknownOperationException") {
					return nil, []string{fmt.Sprintf("%s: skipped model customization inventory because this regional Bedrock API does not support it", regionalCfg.Region)}, count, nil
				}
				return nil, evidence, count, err
			}
			for _, summary := range page.ModelCustomizationJobSummaries {
				count++
				job, err := client.GetModelCustomizationJob(ctx, &bedrock.GetModelCustomizationJobInput{JobIdentifier: summary.JobArn})
				if err != nil {
					return nil, evidence, count, fmt.Errorf("get customization job %s: %w", aws.ToString(summary.JobName), err)
				}
				trainingURI := "not reported"
				if job.TrainingDataConfig != nil && aws.ToString(job.TrainingDataConfig.S3Uri) != "" {
					trainingURI = aws.ToString(job.TrainingDataConfig.S3Uri)
				}
				evidence = append(evidence, fmt.Sprintf("%s: customization job %s (%s, %s), training data %s", regionalCfg.Region, aws.ToString(summary.JobName), summary.CustomizationType, summary.Status, trainingURI))
			}
		}
		sort.Strings(evidence)
		return nil, evidence, count, nil
	})
	return MarkNotInUse(result, "no Bedrock model customization jobs were found in the scanned regions"), err
}

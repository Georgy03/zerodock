package checks

// These controls intentionally use the Bedrock Agent control plane rather
// than guessing from model invocation telemetry: an agent's resource role,
// action-group Lambdas, and knowledge-base sources are the provider-attested
// answer to "what can this AI reach?".

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func init() {
	Register(Check{ID: "aws.bedrock.agent_permissions", Title: "Bedrock agent reach and execution-role permissions", Tier: ProviderAttested, Run: bedrockAgentPermissions})
	Register(Check{ID: "aws.bedrock.knowledge_base_exposure", Title: "Bedrock knowledge-base data-source exposure", Tier: ProviderAttested, Run: bedrockKnowledgeBaseExposure})
	Register(Check{ID: "aws.bedrock.guardrail_enforcement", Title: "Bedrock inference IAM policies enforcing guardrails", Tier: ProviderAttested, Run: bedrockGuardrailEnforcement})
}

func bedrockAgentPermissions(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrockagent.NewFromConfig(regionalCfg)
		p := bedrockagent.NewListAgentsPaginator(client, &bedrockagent.ListAgentsInput{})
		var findings, evidence []string
		count := 0
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, summary := range page.AgentSummaries {
				count++
				agent, err := client.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: summary.AgentId})
				if err != nil {
					return findings, evidence, count, err
				}
				name, role := aws.ToString(summary.AgentName), aws.ToString(agent.Agent.AgentResourceRoleArn)
				guardrail := agent.Agent.GuardrailConfiguration != nil
				evidence = append(evidence, fmt.Sprintf("%s: Bedrock agent %s uses role %s; guardrail attached=%t", regionalCfg.Region, name, role, guardrail))
				if !guardrail {
					findings = append(findings, fmt.Sprintf("%s: Bedrock agent %s has no guardrail attached", regionalCfg.Region, name))
				}
				if role != "" {
					perms, err := rolePermissionClassifications(ctx, iam.NewFromConfig(regionalCfg), role)
					if err != nil {
						return findings, evidence, count, err
					}
					for _, finding := range perms {
						line := fmt.Sprintf("%s: Bedrock agent %s role %s: %s", regionalCfg.Region, name, role, finding)
						if strings.HasPrefix(finding, "SCOPED:") {
							evidence = append(evidence, line)
						} else {
							findings = append(findings, line)
						}
					}
				}
				ag := bedrockagent.NewListAgentActionGroupsPaginator(client, &bedrockagent.ListAgentActionGroupsInput{AgentId: summary.AgentId, AgentVersion: aws.String("DRAFT")})
				for ag.HasMorePages() {
					page, err := ag.NextPage(ctx)
					if err != nil {
						return findings, evidence, count, err
					}
					for _, group := range page.ActionGroupSummaries {
						detail, err := client.GetAgentActionGroup(ctx, &bedrockagent.GetAgentActionGroupInput{AgentId: summary.AgentId, AgentVersion: aws.String("DRAFT"), ActionGroupId: group.ActionGroupId})
						if err != nil {
							return findings, evidence, count, err
						}
						if executor, ok := detail.AgentActionGroup.ActionGroupExecutor.(*bedrockagenttypes.ActionGroupExecutorMemberLambda); ok && executor.Value != "" {
							evidence = append(evidence, fmt.Sprintf("%s: Bedrock agent %s action group %s invokes Lambda %s", regionalCfg.Region, name, aws.ToString(group.ActionGroupName), executor.Value))
						}
					}
				}
			}
		}
		return findings, evidence, count, nil
	})
	return MarkNotInUse(result, "no Bedrock agents were found in the scanned regions"), err
}

// rolePermissionFindings reads inline and attached role policies. It preserves
// the useful distinction between an over-broad action, an over-broad resource,
// and a correctly scoped grant. An unread policy is an error, never a pass.
func rolePermissionFindings(ctx context.Context, client *iam.Client, roleARN string) ([]string, error) {
	classifications, err := rolePermissionClassifications(ctx, client, roleARN)
	if err != nil {
		return nil, err
	}
	var findings []string
	for _, classification := range classifications {
		if !strings.HasPrefix(classification, "SCOPED:") {
			findings = append(findings, classification)
		}
	}
	return findings, nil
}

func rolePermissionClassifications(ctx context.Context, client *iam.Client, roleARN string) ([]string, error) {
	docs, err := rolePolicyDocuments(ctx, client, roleARN)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, doc := range docs {
		out = append(out, broadPolicyStatements(doc)...)
	}
	sort.Strings(out)
	return dedupeStrings(out), nil
}

func rolePolicyDocuments(ctx context.Context, client *iam.Client, roleARN string) ([]string, error) {
	parts := strings.Split(roleARN, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid execution role ARN %q", roleARN)
	}
	role := parts[len(parts)-1]
	var docs []string
	inline, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(role)})
	if err != nil {
		return nil, err
	}
	for _, name := range inline.PolicyNames {
		out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String(name)})
		if err != nil {
			return nil, err
		}
		docs = append(docs, aws.ToString(out.PolicyDocument))
	}
	attached, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(role)})
	if err != nil {
		return nil, err
	}
	for _, policy := range attached.AttachedPolicies {
		meta, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: policy.PolicyArn})
		if err != nil {
			return nil, err
		}
		version, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.PolicyArn, VersionId: meta.Policy.DefaultVersionId})
		if err != nil {
			return nil, err
		}
		docs = append(docs, aws.ToString(version.PolicyVersion.Document))
	}
	var decodedDocs []string
	for _, doc := range docs {
		decoded, err := url.QueryUnescape(doc)
		if err != nil {
			return nil, err
		}
		decodedDocs = append(decodedDocs, decoded)
	}
	return decodedDocs, nil
}

func broadPolicyStatements(document string) []string {
	statements, err := parseIAMStatements(document)
	if err != nil {
		return []string{"could not parse an IAM policy document"}
	}
	var findings []string
	for _, statement := range statements {
		if !strings.EqualFold(statement.Effect, "Allow") {
			continue
		}
		for _, action := range statement.Actions {
			action = strings.ToLower(action)
			if action == "*" || strings.HasSuffix(action, ":*") {
				findings = append(findings, fmt.Sprintf("BROAD PRIVILEGE: %s on %s", action, formatResources(statement.Resources)))
				continue
			}
			if isRelevantDataAction(action) || action == "iam:passrole" {
				if containsWildcard(statement.Resources) {
					findings = append(findings, fmt.Sprintf("BROAD RESOURCE SCOPE: %s on *", action))
				} else {
					findings = append(findings, fmt.Sprintf("SCOPED: %s on %s", action, formatResources(statement.Resources)))
				}
			}
		}
	}
	return dedupeStrings(findings)
}

type iamStatement struct {
	Effect    string
	Actions   []string
	Resources []string
	Condition map[string]any
}

func parseIAMStatements(document string) ([]iamStatement, error) {
	var policy struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &policy); err != nil {
		return nil, err
	}
	var raw []map[string]any
	if err := json.Unmarshal(policy.Statement, &raw); err != nil {
		var one map[string]any
		if oneErr := json.Unmarshal(policy.Statement, &one); oneErr != nil {
			return nil, err
		}
		raw = []map[string]any{one}
	}
	statements := make([]iamStatement, 0, len(raw))
	for _, item := range raw {
		statements = append(statements, iamStatement{
			Effect:    stringValue(item["Effect"]),
			Actions:   stringValues(item["Action"]),
			Resources: stringValues(item["Resource"]),
			Condition: mapValue(item["Condition"]),
		})
	}
	return statements, nil
}

func stringValue(v any) string      { s, _ := v.(string); return s }
func mapValue(v any) map[string]any { m, _ := v.(map[string]any); return m }
func stringValues(v any) []string {
	switch typed := v.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, value := range typed {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}
func formatResources(values []string) string {
	if len(values) == 0 {
		return "no resource"
	}
	return strings.Join(values, ", ")
}
func dedupeStrings(values []string) []string { sort.Strings(values); return compactStrings(values) }
func compactStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
func isRelevantDataAction(action string) bool {
	for _, prefix := range []string{"s3:", "dynamodb:", "rds:", "secretsmanager:"} {
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}
	return false
}

func bedrockKnowledgeBaseExposure(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	result, err := RunAcrossRegionsDetailed(ctx, cfg, func(ctx context.Context, regionalCfg aws.Config) ([]string, []string, int, error) {
		client := bedrockagent.NewFromConfig(regionalCfg)
		s3Client := s3.NewFromConfig(regionalCfg)
		p := bedrockagent.NewListKnowledgeBasesPaginator(client, &bedrockagent.ListKnowledgeBasesInput{})
		var findings, evidence []string
		count := 0
		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return findings, evidence, count, err
			}
			for _, summary := range page.KnowledgeBaseSummaries {
				count++
				kb, err := client.GetKnowledgeBase(ctx, &bedrockagent.GetKnowledgeBaseInput{KnowledgeBaseId: summary.KnowledgeBaseId})
				if err != nil {
					return findings, evidence, count, err
				}
				name := aws.ToString(kb.KnowledgeBase.Name)
				evidence = append(evidence, fmt.Sprintf("%s: knowledge base %s uses execution role %s", regionalCfg.Region, name, aws.ToString(kb.KnowledgeBase.RoleArn)))
				evidence = append(evidence, vectorStoreEvidence(regionalCfg.Region, name, kb.KnowledgeBase.StorageConfiguration))
				if role := aws.ToString(kb.KnowledgeBase.RoleArn); role != "" {
					perms, err := rolePermissionClassifications(ctx, iam.NewFromConfig(regionalCfg), role)
					if err != nil {
						return findings, evidence, count, err
					}
					for _, permission := range perms {
						if !strings.Contains(permission, "s3:") {
							continue
						}
						line := fmt.Sprintf("%s: knowledge base %s execution role %s", regionalCfg.Region, name, permission)
						if strings.HasPrefix(permission, "SCOPED:") {
							evidence = append(evidence, line)
						} else {
							findings = append(findings, line)
						}
					}
				}
				ds := bedrockagent.NewListDataSourcesPaginator(client, &bedrockagent.ListDataSourcesInput{KnowledgeBaseId: summary.KnowledgeBaseId})
				for ds.HasMorePages() {
					page, err := ds.NextPage(ctx)
					if err != nil {
						return findings, evidence, count, err
					}
					for _, source := range page.DataSourceSummaries {
						detail, err := client.GetDataSource(ctx, &bedrockagent.GetDataSourceInput{KnowledgeBaseId: summary.KnowledgeBaseId, DataSourceId: source.DataSourceId})
						if err != nil {
							return findings, evidence, count, err
						}
						if detail.DataSource.DataSourceConfiguration.S3Configuration != nil {
							bucket := aws.ToString(detail.DataSource.DataSourceConfiguration.S3Configuration.BucketArn)
							evidence = append(evidence, fmt.Sprintf("%s: knowledge base %s retrieves from S3 %s", regionalCfg.Region, name, bucket))
							bucketFindings, err := knowledgeBaseBucketFindings(ctx, regionalCfg, s3Client, bucket)
							if err != nil {
								return findings, evidence, count, err
							}
							for _, finding := range bucketFindings {
								findings = append(findings, fmt.Sprintf("%s: knowledge base %s %s", regionalCfg.Region, name, finding))
							}
						}
					}
				}
			}
		}
		return findings, evidence, count, nil
	})
	return MarkNotInUse(result, "no Bedrock knowledge bases were found in the scanned regions"), err
}

func vectorStoreEvidence(region, name string, config *bedrockagenttypes.StorageConfiguration) string {
	if config == nil {
		return fmt.Sprintf("%s: knowledge base %s has no vector-store configuration", region, name)
	}
	switch config.Type {
	case bedrockagenttypes.KnowledgeBaseStorageTypeOpensearchServerless, bedrockagenttypes.KnowledgeBaseStorageTypeOpensearchManagedCluster:
		return fmt.Sprintf("%s: knowledge base %s uses %s; network policy is observable from AWS but not evaluated by this control", region, name, config.Type)
	case bedrockagenttypes.KnowledgeBaseStorageTypePinecone, bedrockagenttypes.KnowledgeBaseStorageTypeRedisEnterpriseCloud, bedrockagenttypes.KnowledgeBaseStorageTypeMongoDbAtlas:
		return fmt.Sprintf("%s: knowledge base %s uses %s; underlying network restriction is NOT PROVIDER-VERIFIABLE FROM AWS", region, name, config.Type)
	default:
		return fmt.Sprintf("%s: knowledge base %s uses vector store %s", region, name, config.Type)
	}
}

func knowledgeBaseBucketFindings(ctx context.Context, cfg aws.Config, listClient *s3.Client, bucketARN string) ([]string, error) {
	bucket := strings.TrimPrefix(bucketARN, "arn:aws:s3:::")
	if bucket == "" || strings.Contains(bucket, "/") {
		return []string{"references an invalid S3 bucket ARN " + bucketARN}, nil
	}
	region, err := bucketRegion(ctx, listClient, bucket)
	if err != nil {
		return nil, fmt.Errorf("get S3 bucket %s location: %w", bucket, err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.Region = region })
	public, reason, err := bucketIsPublic(ctx, client, bucket)
	if err != nil {
		return nil, fmt.Errorf("inspect S3 bucket %s public access: %w", bucket, err)
	}
	var findings []string
	if public {
		findings = append(findings, fmt.Sprintf("HIGH: retrieves from publicly accessible S3 bucket %s (%s)", bucket, reason))
	}
	if _, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(bucket)}); err != nil {
		if isNoSuchConfig(err) {
			findings = append(findings, fmt.Sprintf("retrieves from S3 bucket %s without default encryption", bucket))
		} else {
			return nil, fmt.Errorf("inspect S3 bucket %s encryption: %w", bucket, err)
		}
	}
	return findings, nil
}

// bedrockGuardrailEnforcement examines IAM allow statements that can invoke a
// Bedrock model. It does not claim a full IAM evaluation (SCPs and explicit
// denies may further restrict access); it proves whether the allow itself
// requires bedrock:GuardrailIdentifier.
func bedrockGuardrailEnforcement(ctx context.Context, cfg aws.Config, _ time.Time) (Result, error) {
	client := iam.NewFromConfig(cfg)
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	var findings, evidence []string
	count := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return Result{}, err
		}
		for _, role := range page.Roles {
			docs, err := rolePolicyDocuments(ctx, client, aws.ToString(role.Arn))
			if err != nil {
				return Result{}, fmt.Errorf("read policies for role %s: %w", aws.ToString(role.RoleName), err)
			}
			for _, doc := range docs {
				statements, err := parseIAMStatements(doc)
				if err != nil {
					return Result{}, fmt.Errorf("parse policy for role %s: %w", aws.ToString(role.RoleName), err)
				}
				for _, statement := range statements {
					if !strings.EqualFold(statement.Effect, "Allow") || !allowsBedrockInference(statement.Actions) {
						continue
					}
					count++
					if hasGuardrailCondition(statement.Condition) {
						evidence = append(evidence, fmt.Sprintf("IAM role %s requires bedrock:GuardrailIdentifier for Bedrock inference", aws.ToString(role.RoleName)))
					} else {
						findings = append(findings, fmt.Sprintf("IAM role %s allows Bedrock inference without requiring bedrock:GuardrailIdentifier", aws.ToString(role.RoleName)))
					}
				}
			}
		}
	}
	if count == 0 {
		return Result{Status: StatusNotInUse, Evidence: []string{"no IAM allow statements for Bedrock inference were found"}}, nil
	}
	if len(findings) > 0 {
		return Result{Status: StatusFail, Findings: findings, Evidence: evidence, Count: count}, nil
	}
	return Result{Status: StatusPass, Evidence: evidence, Count: count}, nil
}

func allowsBedrockInference(actions []string) bool {
	for _, action := range actions {
		action = strings.ToLower(action)
		// Action "*" is a generic administrator grant. It can permit a
		// future Bedrock invocation, but does not prove this role is an
		// applicable Bedrock inference path. Requiring guardrails from that
		// alone would turn every admin role into a misleading AI finding.
		if action == "bedrock:*" || strings.HasPrefix(action, "bedrock:invokemodel") || strings.HasPrefix(action, "bedrock:converse") {
			return true
		}
	}
	return false
}
func hasGuardrailCondition(condition map[string]any) bool {
	for _, operator := range condition {
		if nested, ok := operator.(map[string]any); ok {
			for key := range nested {
				if strings.EqualFold(key, "bedrock:GuardrailIdentifier") {
					return true
				}
			}
		}
	}
	return false
}

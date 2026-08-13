package checks

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/smithy-go"
)

func TestBedrockLoggingEnabledRecognizesEveryPromptModality(t *testing.T) {
	if bedrockLoggingEnabled(&bedrocktypes.LoggingConfig{}) {
		t.Fatal("empty logging config must be disabled")
	}
	for name, config := range map[string]*bedrocktypes.LoggingConfig{
		"text":      {TextDataDeliveryEnabled: aws.Bool(true)},
		"image":     {ImageDataDeliveryEnabled: aws.Bool(true)},
		"embedding": {EmbeddingDataDeliveryEnabled: aws.Bool(true)},
		"video":     {VideoDataDeliveryEnabled: aws.Bool(true)},
		"audio":     {AudioDataDeliveryEnabled: aws.Bool(true)},
	} {
		if !bedrockLoggingEnabled(config) {
			t.Errorf("%s logging was not recognized as enabled", name)
		}
	}
}

func TestActiveFoundationModelAgreementIsAccountSpecific(t *testing.T) {
	if hasAccountSpecificThirdPartyAgreement("Anthropic", nil) {
		t.Fatal("a catalog model without agreement data must not become account inventory")
	}
	for _, status := range []bedrocktypes.AgreementStatus{
		bedrocktypes.AgreementStatusPending,
		bedrocktypes.AgreementStatusNotAvailable,
		bedrocktypes.AgreementStatusError,
	} {
		if hasAccountSpecificThirdPartyAgreement("Anthropic", &bedrocktypes.AgreementAvailability{Status: status}) {
			t.Fatalf("agreement status %s must not be reported as active", status)
		}
	}
	available := &bedrocktypes.AgreementAvailability{Status: bedrocktypes.AgreementStatusAvailable}
	if !hasAccountSpecificThirdPartyAgreement("Anthropic", available) {
		t.Fatal("AVAILABLE agreement should be included in account inventory")
	}
	if hasAccountSpecificThirdPartyAgreement("Amazon", available) {
		t.Fatal("first-party Amazon model availability must not be reported as a customer agreement")
	}
}

func TestUnknownOperationDetectionIsExact(t *testing.T) {
	unknown := &smithy.GenericAPIError{Code: "UnknownOperationException", Message: "Unknown Operation"}
	if !isAWSAPIErrorCode(unknown, "UnknownOperationException") {
		t.Fatal("structured UnknownOperationException was not recognized")
	}
	for _, err := range []error{
		&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"},
		errors.New("UnknownOperationException: unstructured text"),
	} {
		if isAWSAPIErrorCode(err, "UnknownOperationException") {
			t.Fatalf("unrelated error %q was incorrectly treated as regional unavailability", err)
		}
	}
}

func TestPolicyAllowsUnrestrictedPublic(t *testing.T) {
	public := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"logs:PutLogEvents","Resource":"*"}]}`
	if !policyAllowsUnrestrictedPublic(public, "arn:aws:logs:us-east-1:123:log-group:bedrock:*") {
		t.Fatal("unconditional wildcard principal should be public")
	}
	conditioned := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"logs:PutLogEvents","Resource":"*","Condition":{"StringEquals":{"aws:SourceAccount":"123"}}}]}`
	if policyAllowsUnrestrictedPublic(conditioned, "arn:aws:logs:us-east-1:123:log-group:bedrock:*") {
		t.Fatal("conditioned wildcard service delivery must not be labeled public")
	}
	unrelated := `{"Statement":[{"Effect":"Allow","Principal":"*","Resource":"arn:aws:logs:us-east-1:123:log-group:other:*"}]}`
	if policyAllowsUnrestrictedPublic(unrelated, "arn:aws:logs:us-east-1:123:log-group:bedrock:*") {
		t.Fatal("public policy for an unrelated log group must not taint the Bedrock destination")
	}
}

func TestMarkNotInUseNeverHidesFailureOrError(t *testing.T) {
	if got := MarkNotInUse(Result{Status: StatusPass}, "none"); got.Status != StatusNotInUse {
		t.Fatalf("clean zero result = %q, want not_in_use", got.Status)
	}
	for _, status := range []string{StatusFail, StatusError} {
		if got := MarkNotInUse(Result{Status: status}, "none"); got.Status != status {
			t.Fatalf("%s became %s", status, got.Status)
		}
	}
}

func TestPolicyPermissionLabelsDistinguishPrivilegeFromScope(t *testing.T) {
	document := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-kb/*"}]}`
	got := broadPolicyStatements(document)
	want := map[string]bool{
		"BROAD PRIVILEGE: s3:* on *":                     false,
		"BROAD RESOURCE SCOPE: s3:getobject on *":        false,
		"SCOPED: s3:getobject on arn:aws:s3:::acme-kb/*": false,
	}
	for _, label := range got {
		if _, ok := want[label]; ok {
			want[label] = true
		}
	}
	for label, found := range want {
		if !found {
			t.Errorf("missing %q in %#v", label, got)
		}
	}
}

func TestGuardrailConditionDetection(t *testing.T) {
	if !hasGuardrailCondition(map[string]any{"StringEquals": map[string]any{"bedrock:GuardrailIdentifier": "arn:aws:bedrock:..."}}) {
		t.Fatal("guardrail condition was not recognized")
	}
	if hasGuardrailCondition(map[string]any{"StringEquals": map[string]any{"aws:PrincipalAccount": "123"}}) {
		t.Fatal("unrelated condition was incorrectly recognized")
	}
}

func TestGuardrailEnforcementOnlyUsesExplicitBedrockInferenceActions(t *testing.T) {
	if allowsBedrockInference([]string{"*"}) {
		t.Fatal("generic administrator action must not become a confirmed Bedrock inference path")
	}
	if !allowsBedrockInference([]string{"bedrock:InvokeModel"}) {
		t.Fatal("explicit Bedrock inference action was not recognized")
	}
}

func TestAIChecksAreRegisteredAsProviderAttested(t *testing.T) {
	want := map[string]bool{
		"aws.bedrock.invocation_logging":      false,
		"aws.bedrock.guardrails":              false,
		"aws.bedrock.model_access":            false,
		"aws.bedrock.customization_jobs":      false,
		"aws.bedrock.agent_permissions":       false,
		"aws.bedrock.knowledge_base_exposure": false,
		"aws.bedrock.guardrail_enforcement":   false,
		"aws.sagemaker.endpoint_encryption":   false,
		"aws.sagemaker.endpoint_network":      false,
		"aws.sagemaker.notebook_internet":     false,
		"aws.sagemaker.notebook_encryption":   false,
		"aws.sagemaker.network_isolation":     false,
	}
	for _, check := range All {
		if _, ok := want[check.ID]; !ok {
			continue
		}
		want[check.ID] = true
		if check.Tier != ProviderAttested || check.Run == nil {
			t.Errorf("%s is not a runnable ProviderAttested check", check.ID)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("AI check %s was not registered", id)
		}
	}
}

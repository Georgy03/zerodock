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
	if hasActiveFoundationModelAgreement(nil) {
		t.Fatal("a catalog model without agreement data must not become account inventory")
	}
	for _, status := range []bedrocktypes.AgreementStatus{
		bedrocktypes.AgreementStatusPending,
		bedrocktypes.AgreementStatusNotAvailable,
		bedrocktypes.AgreementStatusError,
	} {
		if hasActiveFoundationModelAgreement(&bedrocktypes.AgreementAvailability{Status: status}) {
			t.Fatalf("agreement status %s must not be reported as active", status)
		}
	}
	if !hasActiveFoundationModelAgreement(&bedrocktypes.AgreementAvailability{Status: bedrocktypes.AgreementStatusAvailable}) {
		t.Fatal("AVAILABLE agreement should be included in account inventory")
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

func TestAIChecksAreRegisteredAsProviderAttested(t *testing.T) {
	want := map[string]bool{
		"aws.bedrock.invocation_logging":    false,
		"aws.bedrock.guardrails":            false,
		"aws.bedrock.model_access":          false,
		"aws.bedrock.customization_jobs":    false,
		"aws.sagemaker.endpoint_encryption": false,
		"aws.sagemaker.endpoint_network":    false,
		"aws.sagemaker.notebook_internet":   false,
		"aws.sagemaker.notebook_encryption": false,
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

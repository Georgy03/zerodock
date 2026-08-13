package providers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// FetchVendorSecret reads a provider credential directly from the vendor's
// own AWS Secrets Manager secret. ZeroDock is configured with only its ARN:
// the secret value exists in enclave memory for one scan and is never logged,
// persisted, added to a report, or returned by this package.
func FetchVendorSecret(ctx context.Context, cfg aws.Config, arn string) (string, error) {
	if arn == "" {
		return "", fmt.Errorf("secret ARN is empty")
	}
	out, err := secretsmanager.NewFromConfig(cfg).GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &arn})
	if err != nil {
		return "", fmt.Errorf("get secret %q: %w", arn, err)
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return "", fmt.Errorf("secret %q has no non-empty SecretString", arn)
	}
	return *out.SecretString, nil
}

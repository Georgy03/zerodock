package checks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
)

const minimumPasswordLength = 14

func init() {
	Register(Check{ID: "aws.iam.password_policy", Title: "Missing or weak IAM account password policy", Tier: ProviderAttested, Run: iamPasswordPolicy})
}

func iamPasswordPolicy(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	client := iam.NewFromConfig(cfg)
	out, err := client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		if isNoAccountPasswordPolicy(err) {
			return Result{Status: StatusFail, Findings: []string{"account has no IAM password policy"}, Count: 1}, nil
		}
		return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
	}
	length := int32(0)
	if out.PasswordPolicy != nil && out.PasswordPolicy.MinimumPasswordLength != nil {
		length = *out.PasswordPolicy.MinimumPasswordLength
	}
	if length < minimumPasswordLength {
		return Result{Status: StatusFail, Findings: []string{fmt.Sprintf("IAM password policy minimum length is %d, below the %d-character minimum", length, minimumPasswordLength)}, Count: 1}, nil
	}
	return Result{Status: StatusPass, Count: 1}, nil
}

func isNoAccountPasswordPolicy(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchEntity"
}

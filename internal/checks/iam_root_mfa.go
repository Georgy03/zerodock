package checks

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func init() {
	Register(Check{
		ID:    "aws.iam.root_mfa",
		Title: "Root account without MFA enabled",
		Tier:  ProviderAttested,
		Run:   iamRootMFA,
	})
}

// iamRootMFA checks whether the AWS account's ROOT USER — the very first,
// most powerful login for the whole account, which can do literally
// anything including deleting the entire account — has Multi-Factor
// Authentication (MFA) turned on. MFA means logging in needs both a
// password AND a second proof (like a code from a phone app), so a leaked
// password alone isn't enough to break in. Because the root user is so
// powerful, AWS itself strongly recommends every account protect it with
// MFA.
//
// Unlike the EBS/RDS checks above, this is a GLOBAL check, not a regional
// one: there is exactly one root user per AWS account, not one per region.
// So instead of looping over every region with RunAcrossRegions, we just
// make a single API call.
func iamRootMFA(ctx context.Context, cfg aws.Config, now time.Time) (Result, error) {
	client := iam.NewFromConfig(cfg)

	// GetAccountSummary returns a bag of account-wide numbers and flags.
	// One of them, "AccountMFAEnabled", tells us exactly what we want:
	// 1 if the root user has MFA turned on, 0 if not.
	out, err := client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return Result{Status: StatusError, Findings: []string{describeErr(err)}}, nil
	}

	mfaEnabled := out.SummaryMap["AccountMFAEnabled"]

	if mfaEnabled == 1 {
		return Result{Status: StatusPass, Findings: nil, Count: 1}, nil
	}

	return Result{
		Status:   StatusFail,
		Findings: []string{"root account does not have MFA enabled (AccountMFAEnabled=0)"},
		Count:    1,
	}, nil
}

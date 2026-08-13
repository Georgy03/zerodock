package providers

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ManagementRoleName is the role deploy/onboard.yaml creates directly in
// the customer's AWS Organizations management account (the one account a
// service-managed StackSet can never reach) — see MemberRoleName for its
// counterpart in every other account.
const ManagementRoleName = "ZeroDockScannerRole"

// maxMemberAccountFanout bounds how many member-role AssumeRole attempts
// run concurrently while polling onboarding status, so a very large
// organization can't turn one status poll into an unbounded burst of STS
// calls.
const maxMemberAccountFanout = 10

// OnboardingStatus is what GET /v1/onboard/{tenant}/status reports back to
// the browser's live counter. It is always computed fresh from AWS, never
// cached or stored — the whole point is that it reflects what's actually
// connected right now.
type OnboardingStatus struct {
	// ManagementRoleConnected is false until deploy/onboard.yaml's stack
	// has finished creating ZeroDockScannerRole in the customer's account
	// AND that role's trust policy actually admits this ExternalId. Every
	// other field is meaningless while this is false.
	ManagementRoleConnected bool

	// ScopeVerified is true only when an AWS Organization was found via
	// ListAccounts — i.e. TotalAccounts reflects a real, API-confirmed
	// account boundary rather than a single-account guess.
	ScopeVerified bool

	// NoOrganization is true when the management account genuinely has no
	// AWS Organization (AWSOrganizationsNotInUseException), as opposed to
	// an org existing but not yet fully enumerable.
	NoOrganization bool

	TotalAccounts     int
	ConnectedAccounts int
}

type stsAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// CheckOnboardingStatus assumes ZeroDockScannerRole in the customer's
// management account using baseCfg (ZeroDock's own AWS identity), then —
// as soon as that succeeds — enumerates the organization and fans out an
// AssumeRole probe into ZeroDockScannerMemberRole in every other account,
// so the browser's counter can show "N of M" the moment the management
// role exists, without waiting for the member-account StackSet to finish
// rolling out everywhere.
func CheckOnboardingStatus(ctx context.Context, baseCfg aws.Config, customerAccountID, tenantID string) (OnboardingStatus, error) {
	stsClient := sts.NewFromConfig(baseCfg)

	mgmtCfg, err := assumeInto(ctx, stsClient, baseCfg, customerAccountID, ManagementRoleName, tenantID)
	if err != nil {
		var notConnected *notConnectedError
		if errors.As(err, &notConnected) {
			return OnboardingStatus{}, nil
		}
		return OnboardingStatus{}, fmt.Errorf("assume management role: %w", err)
	}

	scope, err := EnumerateOrganization(ctx, mgmtCfg, customerAccountID)
	if err != nil {
		return OnboardingStatus{}, fmt.Errorf("enumerate organization: %w", err)
	}

	if scope.NoOrganization {
		return OnboardingStatus{
			ManagementRoleConnected: true,
			ScopeVerified:           false,
			NoOrganization:          true,
			TotalAccounts:           1,
			ConnectedAccounts:       1,
		}, nil
	}

	memberStsClient := sts.NewFromConfig(baseCfg)
	connected := countConnectedMembers(ctx, memberStsClient, baseCfg, scope.Accounts, customerAccountID, tenantID)

	return OnboardingStatus{
		ManagementRoleConnected: true,
		ScopeVerified:           true,
		TotalAccounts:           len(scope.Accounts),
		ConnectedAccounts:       connected,
	}, nil
}

// countConnectedMembers probes every account in accounts (other than
// customerAccountID, which is already known-connected — that's how we got
// here) with a bounded-concurrency AssumeRole attempt, and returns the
// total connected count including the management account itself.
func countConnectedMembers(ctx context.Context, client stsAPI, baseCfg aws.Config, accounts []string, customerAccountID, tenantID string) int {
	sem := make(chan struct{}, maxMemberAccountFanout)
	var wg sync.WaitGroup
	var mu sync.Mutex
	connected := 1 // the management account itself

	for _, accountID := range accounts {
		if accountID == customerAccountID {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(accountID string) {
			defer wg.Done()
			defer func() { <-sem }()

			roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, MemberRoleName)
			_, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{
				RoleArn:         aws.String(roleArn),
				RoleSessionName: aws.String("zerodock-onboarding-status"),
				ExternalId:      aws.String(tenantID),
				DurationSeconds: aws.Int32(900),
			})
			if err != nil {
				return
			}
			mu.Lock()
			connected++
			mu.Unlock()
		}(accountID)
	}
	wg.Wait()
	return connected
}

// notConnectedError distinguishes "the role doesn't exist or doesn't trust
// us yet" (an expected, transient state while onboarding is in progress)
// from a genuine AWS API failure worth surfacing as an error.
type notConnectedError struct{ cause error }

func (e *notConnectedError) Error() string { return e.cause.Error() }
func (e *notConnectedError) Unwrap() error { return e.cause }

func assumeInto(ctx context.Context, client stsAPI, baseCfg aws.Config, accountID, roleName, tenantID string) (aws.Config, error) {
	roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	out, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String("zerodock-onboarding-status"),
		ExternalId:      aws.String(tenantID),
		DurationSeconds: aws.Int32(900),
	})
	if err != nil {
		// The role not existing yet, and the trust policy rejecting us
		// (wrong or missing ExternalId, StackSet still propagating),
		// both surface as generic AssumeRole failures — STS doesn't
		// distinguish "role missing" from "access denied" in a way this
		// package can reliably type-switch on. Either way, this is an
		// expected, transient state while onboarding is in progress, not
		// a hard failure worth surfacing as an error to the poller.
		return aws.Config{}, &notConnectedError{cause: err}
	}

	assumedCfg := baseCfg.Copy()
	assumedCfg.Credentials = aws.NewCredentialsCache(staticAssumedCredentials{out})
	return assumedCfg, nil
}

// staticAssumedCredentials adapts one sts.AssumeRoleOutput into an
// aws.CredentialsProvider — this status check is short-lived enough
// (a handful of API calls within one HTTP request) that refreshing
// credentials mid-check is never needed.
type staticAssumedCredentials struct {
	out *sts.AssumeRoleOutput
}

func (c staticAssumedCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	creds := c.out.Credentials
	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		Expires:         aws.ToTime(creds.Expiration),
		CanExpire:       true,
	}, nil
}

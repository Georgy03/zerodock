package providers

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// MemberRoleName is intentionally a dedicated read-only scanner role. Never
// replace it with OrganizationAccountAccessRole: that role is administrative,
// whereas ZeroDock needs only the SecurityAudit permissions deployed by
// deploy/member-role.yaml.
const MemberRoleName = "ZeroDockScannerMemberRole"

// OrganizationScope is the result of asking AWS Organizations for the full
// account boundary. Accounts contains every account ID ListAccounts returned,
// sorted so the attested wire format is stable across otherwise identical
// scans. NoOrganization is true only for AWS's explicit
// AWSOrganizationsNotInUseException, never for AccessDenied or another error.
type OrganizationScope struct {
	OrganizationID string
	NoOrganization bool
	Accounts       []string
}

type organizationsAPI interface {
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

// EnumerateOrganization calls the Organizations global endpoint in us-east-1.
// A genuine no-organization response falls back to the caller's single account;
// every other failure is returned so the report can expose enumeration as
// unverified rather than silently presenting one account as the whole estate.
func EnumerateOrganization(ctx context.Context, cfg aws.Config, currentAccountID string) (OrganizationScope, error) {
	organizationsCfg := cfg.Copy()
	organizationsCfg.Region = "us-east-1"
	return enumerateOrganization(ctx, organizations.NewFromConfig(organizationsCfg), currentAccountID)
}

func enumerateOrganization(ctx context.Context, client organizationsAPI, currentAccountID string) (OrganizationScope, error) {
	described, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		var notInUse *organizationstypes.AWSOrganizationsNotInUseException
		if errors.As(err, &notInUse) {
			return OrganizationScope{
				NoOrganization: true,
				Accounts:       []string{currentAccountID},
			}, nil
		}
		return OrganizationScope{}, fmt.Errorf("describe organization: %w", err)
	}
	if described.Organization == nil || aws.ToString(described.Organization.Id) == "" {
		return OrganizationScope{}, fmt.Errorf("describe organization returned no organization ID")
	}

	accountSet := make(map[string]struct{})
	var nextToken *string
	for {
		page, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: nextToken})
		if err != nil {
			return OrganizationScope{}, fmt.Errorf("list organization accounts: %w", err)
		}
		for _, account := range page.Accounts {
			if id := aws.ToString(account.Id); id != "" {
				accountSet[id] = struct{}{}
			}
		}
		// AWS explicitly requires callers to continue until NextToken is nil,
		// even when a page happens to contain zero accounts.
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		nextToken = page.NextToken
	}

	accounts := make([]string, 0, len(accountSet))
	for id := range accountSet {
		accounts = append(accounts, id)
	}
	sort.Strings(accounts)
	if len(accounts) == 0 {
		return OrganizationScope{}, fmt.Errorf("list organization accounts returned an empty account list")
	}
	if _, ok := accountSet[currentAccountID]; !ok {
		return OrganizationScope{}, fmt.Errorf("list organization accounts did not include current account %s", currentAccountID)
	}

	return OrganizationScope{
		OrganizationID: aws.ToString(described.Organization.Id),
		Accounts:       accounts,
	}, nil
}

// AssumeMemberRole returns an AWS config backed by temporary credentials for
// the dedicated member role, and retrieves those credentials immediately.
// Eager retrieval makes a denied/missing role an account-scope error now,
// instead of letting every individual check fail later with the same message.
func AssumeMemberRole(ctx context.Context, cfg aws.Config, accountID string) (aws.Config, error) {
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, MemberRoleName)
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = "zerodock-scanner"
	})
	credentials := aws.NewCredentialsCache(provider)
	if _, err := credentials.Retrieve(ctx); err != nil {
		return aws.Config{}, fmt.Errorf("assume %s: %w", roleARN, err)
	}

	memberCfg := cfg.Copy()
	memberCfg.Credentials = credentials
	return memberCfg, nil
}

package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	organizationstypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

type fakeOrganizations struct {
	describeOutput *organizations.DescribeOrganizationOutput
	describeErr    error
	listOutputs    []*organizations.ListAccountsOutput
	listCalls      int
}

func (f *fakeOrganizations) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return f.describeOutput, f.describeErr
}

func (f *fakeOrganizations) ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	output := f.listOutputs[f.listCalls]
	f.listCalls++
	return output, nil
}

func TestEnumerateOrganizationPaginatesSortsAndDeduplicates(t *testing.T) {
	client := &fakeOrganizations{
		describeOutput: &organizations.DescribeOrganizationOutput{
			Organization: &organizationstypes.Organization{Id: aws.String("o-example")},
		},
		listOutputs: []*organizations.ListAccountsOutput{
			{Accounts: nil, NextToken: aws.String("next")},
			{Accounts: []organizationstypes.Account{
				{Id: aws.String("222222222222")},
				{Id: aws.String("111111111111")},
				{Id: aws.String("222222222222")},
			}},
		},
	}

	scope, err := enumerateOrganization(context.Background(), client, "111111111111")
	if err != nil {
		t.Fatalf("enumerateOrganization: %v", err)
	}
	if scope.OrganizationID != "o-example" || scope.NoOrganization {
		t.Fatalf("unexpected scope: %+v", scope)
	}
	want := []string{"111111111111", "222222222222"}
	if len(scope.Accounts) != len(want) || scope.Accounts[0] != want[0] || scope.Accounts[1] != want[1] {
		t.Fatalf("accounts = %v, want %v", scope.Accounts, want)
	}
	if client.listCalls != 2 {
		t.Fatalf("ListAccounts calls = %d, want 2", client.listCalls)
	}
}

func TestEnumerateOrganizationExplicitNoOrganizationFallback(t *testing.T) {
	client := &fakeOrganizations{describeErr: &organizationstypes.AWSOrganizationsNotInUseException{}}
	scope, err := enumerateOrganization(context.Background(), client, "111111111111")
	if err != nil {
		t.Fatalf("enumerateOrganization: %v", err)
	}
	if !scope.NoOrganization || len(scope.Accounts) != 1 || scope.Accounts[0] != "111111111111" {
		t.Fatalf("unexpected no-organization scope: %+v", scope)
	}
	if client.listCalls != 0 {
		t.Fatal("ListAccounts must not run after an explicit no-organization response")
	}
}

func TestEnumerateOrganizationDoesNotDisguiseAccessDeniedAsNoOrganization(t *testing.T) {
	client := &fakeOrganizations{describeErr: errors.New("AccessDenied")}
	scope, err := enumerateOrganization(context.Background(), client, "111111111111")
	if err == nil {
		t.Fatal("expected enumeration error")
	}
	if scope.NoOrganization {
		t.Fatal("AccessDenied must never be represented as no_organization=true")
	}
}

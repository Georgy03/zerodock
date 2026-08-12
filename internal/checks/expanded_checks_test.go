package checks

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/smithy-go"
)

func TestExpandedCheckLibrary_RegisteredAndProviderAttested(t *testing.T) {
	wanted := []string{
		"aws.kms.key_rotation",
		"aws.cloudtrail.log_encryption",
		"aws.cloudtrail.log_validation",
		"aws.s3.versioning",
		"aws.s3.encryption",
		"aws.ebs.snapshot_encryption",
		"aws.ebs.default_encryption",
		"aws.rds.tls_enforcement",
		"aws.guardduty.enabled",
		"aws.iam.password_policy",
	}
	registered := make(map[string]Check, len(All))
	for _, check := range All {
		if _, exists := registered[check.ID]; exists {
			t.Errorf("duplicate check ID %q", check.ID)
		}
		registered[check.ID] = check
	}
	for _, id := range wanted {
		check, ok := registered[id]
		if !ok {
			t.Errorf("check %q is not registered", id)
			continue
		}
		if check.Tier != ProviderAttested {
			t.Errorf("check %q tier = %q, want %q", id, check.Tier, ProviderAttested)
		}
		if check.Run == nil {
			t.Errorf("check %q has no Run function", id)
		}
	}
}

func TestNoAccountPasswordPolicy_IsFailCondition(t *testing.T) {
	missing := &smithy.GenericAPIError{Code: "NoSuchEntity", Message: "The Password Policy with domain name does not exist."}
	if !isNoAccountPasswordPolicy(missing) {
		t.Error("NoSuchEntity must be treated as an absent password policy, not a check error")
	}
	denied := &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"}
	if isNoAccountPasswordPolicy(denied) {
		t.Error("AccessDenied must remain a check error")
	}
}

func TestDistinctTrails_DeduplicatesShadowTrails(t *testing.T) {
	trails := distinctTrails([]types.Trail{
		{TrailARN: aws.String("arn:trail:b"), Name: aws.String("b-shadow")},
		{TrailARN: aws.String("arn:trail:a"), Name: aws.String("a")},
		{TrailARN: aws.String("arn:trail:b"), Name: aws.String("b-home")},
	})
	if len(trails) != 2 || trailName(trails[0]) != "arn:trail:a" || trailName(trails[1]) != "arn:trail:b" {
		t.Fatalf("distinctTrails = %#v", trails)
	}
}

func TestTLSParameterForFamily(t *testing.T) {
	tests := []struct {
		family, parameter string
	}{
		{"postgres16", "rds.force_ssl"},
		{"aurora-postgresql15", "rds.force_ssl"},
		{"mysql8.0", "require_secure_transport"},
		{"aurora-mysql8.0", "require_secure_transport"},
	}
	for _, test := range tests {
		got, ok := tlsParameterForFamily(test.family)
		if !ok || got.name != test.parameter {
			t.Errorf("tlsParameterForFamily(%q) = (%q, %t), want (%q, true)", test.family, got.name, ok, test.parameter)
		}
	}
	if _, ok := tlsParameterForFamily("oracle-ee-19"); ok {
		t.Error("unsupported Oracle family should be skipped")
	}
}

func TestBoolParameterIsOff(t *testing.T) {
	for _, value := range []string{"0", "off", "FALSE"} {
		if insecure, recognized := boolParameterIsOff(value); !recognized || !insecure {
			t.Errorf("%q = (%t, %t), want (true, true)", value, insecure, recognized)
		}
	}
	for _, value := range []string{"1", "on", "TRUE"} {
		if insecure, recognized := boolParameterIsOff(value); !recognized || insecure {
			t.Errorf("%q = (%t, %t), want (false, true)", value, insecure, recognized)
		}
	}
	if _, recognized := boolParameterIsOff("sometimes"); recognized {
		t.Error("unexpected parameter value should not be treated as secure")
	}
}

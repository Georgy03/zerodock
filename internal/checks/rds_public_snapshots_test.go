package checks

import (
	"testing"

	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// str is a tiny helper: Go structs from the AWS SDK often want a *string
// (a pointer to a string) instead of a plain string, so this just gives us
// a one-line way to get a pointer to a string literal in our test data.
func str(s string) *string { return &s }

// TestSnapshotAttributesArePublic checks the logic that decides "is this
// snapshot's restore attribute set to 'all AWS accounts'?" — again using
// table-driven tests, so we can cover several realistic scenarios without
// writing near-duplicate test functions for each one.
func TestSnapshotAttributesArePublic(t *testing.T) {
	tests := []struct {
		name   string
		result *rdstypes.DBSnapshotAttributesResult
		want   bool
	}{
		{
			name:   "nil result",
			result: nil,
			want:   false,
		},
		{
			name: "public restore attribute",
			result: &rdstypes.DBSnapshotAttributesResult{
				DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
					{AttributeName: str("restore"), AttributeValues: []string{"all"}},
				},
			},
			want: true,
		},
		{
			name: "restricted restore attribute (specific account IDs)",
			result: &rdstypes.DBSnapshotAttributesResult{
				DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
					{AttributeName: str("restore"), AttributeValues: []string{"111122223333"}},
				},
			},
			want: false,
		},
		{
			name: "no restore attribute at all",
			result: &rdstypes.DBSnapshotAttributesResult{
				DBSnapshotAttributes: []rdstypes.DBSnapshotAttribute{
					{AttributeName: str("some-other-attr"), AttributeValues: []string{"all"}},
				},
			},
			want: false,
		},
		{
			name: "empty attributes",
			result: &rdstypes.DBSnapshotAttributesResult{
				DBSnapshotAttributes: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := snapshotAttributesArePublic(tt.result); got != tt.want {
				t.Errorf("snapshotAttributesArePublic() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRDSPublicSnapshotsCheck_Registered confirms the check registered
// itself correctly, the same way TestEC2OpenSGCheck_Registered does for
// the security group check.
func TestRDSPublicSnapshotsCheck_Registered(t *testing.T) {
	found := false
	for _, c := range All {
		if c.ID == "aws.rds.public_snapshots" {
			found = true
			if c.Tier != ProviderAttested {
				t.Errorf("tier = %v, want %v", c.Tier, ProviderAttested)
			}
		}
	}
	if !found {
		t.Fatal("aws.rds.public_snapshots was not registered")
	}
}

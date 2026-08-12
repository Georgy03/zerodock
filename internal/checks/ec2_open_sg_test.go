package checks

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// TestPermissionCoversPort checks the small helper function that decides
// whether a security group rule's port range includes a specific port
// we're interested in. We test it directly (without needing a real AWS
// account) using "table-driven" tests: a list of {input, expected output}
// cases that all run through the same test logic.
func TestPermissionCoversPort(t *testing.T) {
	tests := []struct {
		name       string
		fromPort   *int32
		toPort     *int32
		port       int32
		wantCovers bool
	}{
		{"exact match", aws.Int32(22), aws.Int32(22), 22, true},
		{"in range", aws.Int32(20), aws.Int32(25), 22, true},
		{"below range", aws.Int32(23), aws.Int32(25), 22, false},
		{"above range", aws.Int32(1), aws.Int32(21), 22, false},
		{"all ports (protocol -1)", nil, nil, 22, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm := ec2types.IpPermission{FromPort: tt.fromPort, ToPort: tt.toPort}
			if got := permissionCoversPort(perm, tt.port); got != tt.wantCovers {
				t.Errorf("permissionCoversPort(%v-%v, %d) = %v, want %v", tt.fromPort, tt.toPort, tt.port, got, tt.wantCovers)
			}
		})
	}
}

// TestOpenToInternet checks the helper that decides whether a rule allows
// traffic from literally anywhere on the internet (0.0.0.0/0 for IPv4,
// ::/0 for IPv6), versus only from a specific, limited address range.
func TestOpenToInternet(t *testing.T) {
	tests := []struct {
		name     string
		perm     ec2types.IpPermission
		wantCidr string
		wantOpen bool
	}{
		{
			name: "public ipv4",
			perm: ec2types.IpPermission{
				IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
			},
			wantCidr: "0.0.0.0/0",
			wantOpen: true,
		},
		{
			name: "public ipv6",
			perm: ec2types.IpPermission{
				Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
			},
			wantCidr: "::/0",
			wantOpen: true,
		},
		{
			name: "restricted cidr only",
			perm: ec2types.IpPermission{
				IpRanges: []ec2types.IpRange{{CidrIp: aws.String("10.0.0.0/8")}},
			},
			wantOpen: false,
		},
		{
			name:     "no ranges",
			perm:     ec2types.IpPermission{},
			wantOpen: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCidr, gotOpen := openToInternet(tt.perm)
			if gotOpen != tt.wantOpen {
				t.Fatalf("openToInternet() open = %v, want %v", gotOpen, tt.wantOpen)
			}
			if gotOpen && gotCidr != tt.wantCidr {
				t.Errorf("openToInternet() cidr = %q, want %q", gotCidr, tt.wantCidr)
			}
		})
	}
}

// TestEC2OpenSGCheck_Registered makes sure the check actually registered
// itself into the global checks.All list (via its init() function) with
// the ID and Tier we expect — catching a typo like a mismatched ID before
// it ships.
func TestEC2OpenSGCheck_Registered(t *testing.T) {
	found := false
	for _, c := range All {
		if c.ID == "aws.ec2.open_sg" {
			found = true
			if c.Tier != ProviderAttested {
				t.Errorf("tier = %v, want %v", c.Tier, ProviderAttested)
			}
		}
	}
	if !found {
		t.Fatal("aws.ec2.open_sg was not registered")
	}
}

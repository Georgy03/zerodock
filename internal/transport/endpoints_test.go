package transport

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

// TestEndpointTable_AllPortsUnique catches the easiest way this table
// could break silently: two different hostnames accidentally sharing the
// same vsock port. If that happened, whichever vsock-proxy started last
// for that port would "win", and the other hostname's traffic would
// quietly go to the wrong AWS service instead of failing loudly.
func TestEndpointTable_AllPortsUnique(t *testing.T) {
	seen := make(map[uint32]string)
	for host, port := range hostnameToVsockPort {
		if existing, ok := seen[port]; ok {
			t.Errorf("port %d is used by both %q and %q", port, existing, host)
		}
		seen[port] = host
	}
}

// TestEndpointTable_IAMIsGlobalNotRegional locks in the specific gotcha
// this table exists to get right: IAM has exactly one hostname for the
// whole account, not one per region like every other service here. If
// someone "completes the pattern" and adds regional IAM entries, this
// test catches it.
func TestEndpointTable_IAMIsGlobalNotRegional(t *testing.T) {
	if _, ok := hostnameToVsockPort["iam.amazonaws.com"]; !ok {
		t.Error(`expected "iam.amazonaws.com" (the global IAM endpoint) in the table`)
	}
	for host := range hostnameToVsockPort {
		if host == "iam.us-east-1.amazonaws.com" || host == "iam.us-east-2.amazonaws.com" {
			t.Errorf("found regional IAM entry %q — IAM is a global service with exactly one hostname, see the comment on portIAMGlobal", host)
		}
	}
}

// TestEndpointTable_HasBothRegionsForRegionalServices confirms every
// regional service (as opposed to global IAM and Organizations) has both an us-east-1 and
// us-east-2 entry — a missing one would silently hang any check that
// happens to run in the missing region, per the comment on
// VsockDialer.DialContext.
func TestEndpointTable_HasBothRegionsForRegionalServices(t *testing.T) {
	regionalServices := []string{"ec2", "rds", "s3", "cloudtrail", "sts", "kms", "guardduty", "bedrock", "bedrock-agent", "secretsmanager"}
	for _, svc := range regionalServices {
		for _, region := range []string{"us-east-1", "us-east-2"} {
			host := svc + "." + region + ".amazonaws.com"
			if _, ok := hostnameToVsockPort[host]; !ok {
				t.Errorf("missing endpoint table entry for %q", host)
			}
		}
	}
	for service, pattern := range map[string]string{
		"SageMaker":       "api.sagemaker.%s.amazonaws.com",
		"CloudWatch Logs": "logs.%s.amazonaws.com",
	} {
		for _, region := range []string{"us-east-1", "us-east-2"} {
			host := fmt.Sprintf(pattern, region)
			if _, ok := hostnameToVsockPort[host]; !ok {
				t.Errorf("missing %s endpoint table entry for %q", service, host)
			}
		}
	}
}

// TestEndpointConfigsStayInSync turns the three-way maintenance warning in
// endpoints.go into an executable invariant. A new hostname or port must be
// present in the enclave table, the parent allowlist, and the startup script.
func TestEndpointConfigsStayInSync(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	yamlBytes, err := os.ReadFile(filepath.Join(repoRoot, "deploy", "vsock-proxy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	scriptBytes, err := os.ReadFile(filepath.Join(repoRoot, "deploy", "start-proxies.sh"))
	if err != nil {
		t.Fatal(err)
	}

	yamlHosts := make(map[string]bool)
	for _, match := range regexp.MustCompile(`address:\s*([a-z0-9.-]+)`).FindAllStringSubmatch(string(yamlBytes), -1) {
		yamlHosts[match[1]] = true
	}
	scriptEndpoints := make(map[string]uint32)
	for _, match := range regexp.MustCompile(`"([0-9]+):([a-z0-9.-]+)"`).FindAllStringSubmatch(string(scriptBytes), -1) {
		port, err := strconv.ParseUint(match[1], 10, 32)
		if err != nil {
			t.Fatalf("parse script port %q: %v", match[1], err)
		}
		scriptEndpoints[match[2]] = uint32(port)
	}

	if len(yamlHosts) != len(hostnameToVsockPort) || len(scriptEndpoints) != len(hostnameToVsockPort) {
		t.Fatalf("endpoint count drift: Go=%d YAML=%d script=%d", len(hostnameToVsockPort), len(yamlHosts), len(scriptEndpoints))
	}
	for host, port := range hostnameToVsockPort {
		if !yamlHosts[host] {
			t.Errorf("%q is missing from deploy/vsock-proxy.yaml", host)
		}
		if scriptEndpoints[host] != port {
			t.Errorf("start-proxies.sh maps %q to %d, want %d", host, scriptEndpoints[host], port)
		}
	}
}

func TestEndpointTable_OrganizationsUsesItsGlobalHostedEndpoint(t *testing.T) {
	if _, ok := hostnameToVsockPort["organizations.us-east-1.amazonaws.com"]; !ok {
		t.Error("missing AWS Organizations global endpoint")
	}
	if _, ok := hostnameToVsockPort["organizations.us-east-2.amazonaws.com"]; ok {
		t.Error("Organizations must not be treated as a per-region service")
	}
}

func TestEndpointTable_HasSupabaseManagementEndpoint(t *testing.T) {
	if _, ok := hostnameToVsockPort["api.supabase.com"]; !ok {
		t.Fatal("missing Supabase Management API endpoint")
	}
}

func TestEndpointTable_HasEveryGoogleControlPlaneEndpoint(t *testing.T) {
	for _, host := range []string{
		"cloudresourcemanager.googleapis.com", "compute.googleapis.com",
		"storage.googleapis.com", "iam.googleapis.com", "sqladmin.googleapis.com",
		"logging.googleapis.com", "cloudkms.googleapis.com", "sts.googleapis.com",
	} {
		if _, ok := hostnameToVsockPort[host]; !ok {
			t.Errorf("missing Google endpoint %s", host)
		}
	}
}

func TestVsockPortForHostname_S3VirtualHostedStyle(t *testing.T) {
	tests := []struct {
		host string
		want uint32
	}{
		{host: "customer-backups.s3.us-east-1.amazonaws.com", want: portS3UsEast1},
		{host: "cf-templates-123456789012-us-east-1.s3.us-east-1.amazonaws.com", want: portS3UsEast1},
		{host: "audit-logs.s3.us-east-2.amazonaws.com", want: portS3UsEast2},
	}

	for _, test := range tests {
		got, ok := vsockPortForHostname(test.host)
		if !ok || got != test.want {
			t.Errorf("vsockPortForHostname(%q) = (%d, %t), want (%d, true)", test.host, got, ok, test.want)
		}
	}
}

func TestVsockPortForHostname_RejectsS3Lookalikes(t *testing.T) {
	lookalikes := []string{
		"customer.evil-s3.us-east-1.amazonaws.com",
		"s3.us-east-1.amazonaws.com.attacker.example",
		"customer.s3.us-east-1.amazonaws.com.attacker.example",
	}
	for _, host := range lookalikes {
		if port, ok := vsockPortForHostname(host); ok {
			t.Errorf("vsockPortForHostname(%q) unexpectedly returned port %d", host, port)
		}
	}
}

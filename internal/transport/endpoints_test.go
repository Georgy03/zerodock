package transport

import "testing"

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
// regional service (everything except IAM) has both an us-east-1 and
// us-east-2 entry — a missing one would silently hang any check that
// happens to run in the missing region, per the comment on
// VsockDialer.DialContext.
func TestEndpointTable_HasBothRegionsForRegionalServices(t *testing.T) {
	regionalServices := []string{"ec2", "rds", "s3", "cloudtrail", "sts"}
	for _, svc := range regionalServices {
		for _, region := range []string{"us-east-1", "us-east-2"} {
			host := svc + "." + region + ".amazonaws.com"
			if _, ok := hostnameToVsockPort[host]; !ok {
				t.Errorf("missing endpoint table entry for %q", host)
			}
		}
	}
}

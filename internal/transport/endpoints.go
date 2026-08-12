package transport

import "strings"

// This file is the single source of truth for "which AWS hostname maps to
// which vsock port". It MUST stay in sync with two other places by hand,
// because vsock has no DNS and no service discovery of its own — a vsock
// port number is the ENTIRE address, so both ends of the connection have
// to agree on the numbers ahead of time:
//
//  1. deploy/vsock-proxy.yaml — the allowlist of hostnames the parent's
//     vsock-proxy processes are permitted to forward to.
//  2. deploy/start-proxies.sh — which starts one vsock-proxy process per
//     port/hostname pair listed below, on the PARENT instance.
//
// If you add, remove, or rename a check that talks to a new AWS service,
// update all three together, or the enclave will dial a port nothing is
// listening on and every call to that service will hang until it times
// out — see the big comment on VsockDialer.DialContext for exactly what
// that failure looks like.

// Fixed vsock ports for each AWS API endpoint the scanner talks to. These
// numbers are arbitrary (vsock ports are just an address, like a TCP port)
// — what matters is that this file, vsock-proxy.yaml, and start-proxies.sh
// all agree on the same numbers for the same hostname.
const (
	portEC2UsEast1        = 8101
	portEC2UsEast2        = 8102
	portRDSUsEast1        = 8103
	portRDSUsEast2        = 8104
	portS3UsEast1         = 8105
	portS3UsEast2         = 8106
	portCloudTrailUsEast1 = 8107
	portCloudTrailUsEast2 = 8108
	portSTSUsEast1        = 8109
	portSTSUsEast2        = 8110

	// IAM is a GLOBAL AWS service, not a regional one — unlike every
	// other endpoint in this table, there is only ONE IAM hostname for
	// the whole AWS account, regardless of which region your client is
	// configured for. Giving IAM a "us-east-1" and "us-east-2" entry the
	// same way we did for EC2/RDS/S3/CloudTrail/STS would be wrong: the
	// AWS SDK will only ever ask for iam.amazonaws.com, so a
	// region-suffixed entry would just sit unused while the real
	// hostname resolves to nothing in our table and hangs. This is
	// exactly the "allowlist hostnames wrong, they're region-specific"
	// failure mode to watch for — IAM is the one endpoint where being
	// "region-specific" like the others is itself the bug.
	portIAMGlobal = 8111

	// AWS Organizations is also global, but its single commercial-partition
	// endpoint is hosted in us-east-1.
	portOrganizationsGlobal = 8112
	portKMSUsEast1          = 8113
	portKMSUsEast2          = 8114
	portGuardDutyUsEast1    = 8115
	portGuardDutyUsEast2    = 8116

	// VsockPortCredentials is the dedicated port the enclave connects to
	// ONCE at startup to receive its temporary AWS credentials from the
	// parent — see credentials.go. It's deliberately outside the 810x
	// range above so it's obviously not an AWS API endpoint if you're
	// scanning port numbers later.
	VsockPortCredentials = 8200

	// VsockPortReport is the dedicated port the enclave connects to ONCE,
	// at the very end of a scan, to hand its finished JSON report to the
	// parent — see report.go and deploy/collect-report.py. Traffic on
	// this port flows the OPPOSITE direction from VsockPortCredentials
	// (enclave -> parent, not parent -> enclave), but it's still just
	// "dial the parent on a known port", so it reuses the same
	// VsockDialer machinery.
	VsockPortReport = 8300
)

// hostnameToVsockPort maps every AWS hostname the scanner's checks can
// possibly call to the fixed vsock port that reaches it. VsockDialer looks
// up the hostname it's asked to connect to in this table — see
// DialContext in vsock_dialer.go.
var hostnameToVsockPort = map[string]uint32{
	"ec2.us-east-1.amazonaws.com": portEC2UsEast1,
	"ec2.us-east-2.amazonaws.com": portEC2UsEast2,

	"rds.us-east-1.amazonaws.com": portRDSUsEast1,
	"rds.us-east-2.amazonaws.com": portRDSUsEast2,

	// The AWS SDK v2 always includes the region in the S3 hostname, even
	// for us-east-1 (unlike the older v1 SDK, which had a legacy
	// global-style "s3.amazonaws.com" fallback for that one region) — so
	// both of these are genuinely needed.
	"s3.us-east-1.amazonaws.com": portS3UsEast1,
	"s3.us-east-2.amazonaws.com": portS3UsEast2,

	"cloudtrail.us-east-1.amazonaws.com": portCloudTrailUsEast1,
	"cloudtrail.us-east-2.amazonaws.com": portCloudTrailUsEast2,

	// AWS SDK v2 resolves STS to a REGIONAL endpoint by default (unlike
	// the old global "sts.amazonaws.com" default some SDKs still use),
	// so these two are both needed and "sts.amazonaws.com" is not.
	"sts.us-east-1.amazonaws.com": portSTSUsEast1,
	"sts.us-east-2.amazonaws.com": portSTSUsEast2,

	// One entry, not two — see the comment on portIAMGlobal above.
	"iam.amazonaws.com": portIAMGlobal,

	"organizations.us-east-1.amazonaws.com": portOrganizationsGlobal,

	"kms.us-east-1.amazonaws.com": portKMSUsEast1,
	"kms.us-east-2.amazonaws.com": portKMSUsEast2,

	"guardduty.us-east-1.amazonaws.com": portGuardDutyUsEast1,
	"guardduty.us-east-2.amazonaws.com": portGuardDutyUsEast2,
}

// vsockPortForHostname resolves both ordinary AWS service endpoints and S3's
// virtual-hosted-style bucket endpoints. S3 turns a request for bucket
// "example" into example.s3.us-east-1.amazonaws.com; keeping an entry for
// every possible bucket is impossible, so every bucket hostname for a region
// shares that region's existing S3 tunnel.
//
// The leading dot in the suffix is security-significant. It accepts
// "bucket.s3.us-east-1.amazonaws.com" but rejects lookalikes such as
// "bucket.evil-s3.us-east-1.amazonaws.com" and
// "s3.us-east-1.amazonaws.com.attacker.example".
func vsockPortForHostname(host string) (uint32, bool) {
	if port, ok := hostnameToVsockPort[host]; ok {
		return port, true
	}

	switch {
	case strings.HasSuffix(host, ".s3.us-east-1.amazonaws.com"):
		return portS3UsEast1, true
	case strings.HasSuffix(host, ".s3.us-east-2.amazonaws.com"):
		return portS3UsEast2, true
	}

	return 0, false
}

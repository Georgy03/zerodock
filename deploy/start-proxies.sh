#!/usr/bin/env bash
#
# Run this on the PARENT EC2 instance (the one hosting the enclave) — NOT
# inside the enclave itself. It starts one `vsock-proxy` process per AWS
# endpoint the scanner needs to reach. Each vsock-proxy process listens on
# a vsock port and forwards whatever it receives on to the real AWS
# hostname over the parent's normal network connection — that's the ONLY
# way traffic gets from the enclave (which has no network of its own) out
# to the real internet.
#
# The enclave-side code (internal/transport/endpoints.go) dials the parent
# (vsock context ID 3) on one of these SAME port numbers to reach a given
# AWS hostname. The three files below — this script, endpoints.go, and
# vsock-proxy.yaml — all have to agree on the same port <-> hostname
# pairs, because vsock has no DNS or service discovery: a port number is
# the entire address. If you change one, change all three.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/vsock-proxy.yaml"

if ! command -v vsock-proxy >/dev/null 2>&1; then
	echo "start-proxies.sh: vsock-proxy not found on PATH — install aws-nitro-enclaves-cli on the parent instance" >&2
	exit 1
fi

# port:hostname pairs. Port numbers here MUST exactly match the constants
# in internal/transport/endpoints.go (portEC2UsEast1 = 8101, and so on) —
# see the comment above.
ENDPOINTS=(
	"8101:ec2.us-east-1.amazonaws.com"
	"8102:ec2.us-east-2.amazonaws.com"
	"8103:rds.us-east-1.amazonaws.com"
	"8104:rds.us-east-2.amazonaws.com"
	"8105:s3.us-east-1.amazonaws.com"
	"8106:s3.us-east-2.amazonaws.com"
	# The enclave maps bucket.s3.<region>.amazonaws.com to these fixed S3
	# tunnels. vsock-proxy itself accepts a fixed destination, not a wildcard.
	"8107:cloudtrail.us-east-1.amazonaws.com"
	"8108:cloudtrail.us-east-2.amazonaws.com"
	"8109:sts.us-east-1.amazonaws.com"
	"8110:sts.us-east-2.amazonaws.com"
	# IAM is global — one entry, not one per region. See the matching
	# comment in endpoints.go and vsock-proxy.yaml before "fixing" this.
	"8111:iam.amazonaws.com"
	# Organizations is global but hosted at this us-east-1 endpoint.
	"8112:organizations.us-east-1.amazonaws.com"
)

pids=()

# On exit (including Ctrl-C), stop every vsock-proxy process we started,
# instead of leaving them running in the background forever.
cleanup() {
	echo "start-proxies.sh: stopping ${#pids[@]} vsock-proxy process(es)..."
	kill "${pids[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for entry in "${ENDPOINTS[@]}"; do
	port="${entry%%:*}"
	host="${entry#*:}"

	echo "start-proxies.sh: vsock-proxy $port -> $host:443"
	vsock-proxy "$port" "$host" 443 --config "$CONFIG_FILE" &
	pids+=("$!")
done

echo "start-proxies.sh: ${#pids[@]} vsock-proxy process(es) running. Press Ctrl-C to stop."

# Wait on all of them: if any one dies unexpectedly, `wait -n` returns and
# we exit (triggering cleanup above) rather than silently running with a
# gap in the allowlisted endpoints.
wait -n "${pids[@]}"
echo "start-proxies.sh: a vsock-proxy process exited; stopping the rest." >&2
exit 1

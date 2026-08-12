#!/usr/bin/env bash
#
# Orchestrates one full "run the enclave for real" cycle on the PARENT EC2
# instance:
#   1. Start the three parent-side helpers vsock networking needs: the
#      vsock-proxy processes (AWS API access), the credential server
#      (temporary AWS creds), and the report collector (receives the
#      finished scan report).
#   2. Launch the enclave WITHOUT --debug-mode, so nitro-cli measures and
#      reports real (non-zero) PCR values instead of zeroing them out.
#   3. Wait for the report collector to receive its one report — that's
#      the signal the scan actually finished.
#   4. Tear everything down again: terminate the enclave, stop the helper
#      processes.
#
# Run this on the parent instance, as the target `make run-enclave` calls
# it — not by hand inside the enclave, and not on a machine without
# nitro-cli/docker/an actual Nitro-capable instance type.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EIF_PATH="${1:?usage: run-enclave.sh <path-to-eif>}"
CPU_COUNT="${CPU_COUNT:-2}"
MEMORY_MB="${MEMORY_MB:-2048}"
REPORTS_DIR="${REPORTS_DIR:-reports}"

for tool in docker nitro-cli python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "run-enclave.sh: required tool '$tool' not found on PATH" >&2
		exit 1
	fi
done

helper_pids=()
enclave_id=""

# Runs on any exit path (success, error, Ctrl-C) — terminates the enclave
# (if one was started) and stops every helper process we started, so a
# failed or interrupted run never leaves stray vsock-proxy/Python
# processes, or a running enclave, behind.
cleanup() {
	echo "run-enclave.sh: cleaning up..."
	if [ -n "$enclave_id" ]; then
		nitro-cli terminate-enclave --enclave-id "$enclave_id" 2>/dev/null || true
	fi
	if [ "${#helper_pids[@]}" -gt 0 ]; then
		kill "${helper_pids[@]}" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

echo "run-enclave.sh: starting vsock-proxy processes..."
"$SCRIPT_DIR/start-proxies.sh" &
helper_pids+=("$!")

echo "run-enclave.sh: starting credential server..."
python3 "$SCRIPT_DIR/serve-credentials.py" &
helper_pids+=("$!")

echo "run-enclave.sh: starting report collector..."
python3 "$SCRIPT_DIR/collect-report.py" "$REPORTS_DIR" &
collector_pid="$!"
helper_pids+=("$collector_pid")

# Give the helpers a moment to actually bind their ports before the
# enclave starts trying to reach them — otherwise the scanner's first
# credential fetch could race a credential server that hasn't finished
# starting up yet.
sleep 2

echo "run-enclave.sh: launching enclave from $EIF_PATH (no --debug-mode, so PCRs are real)..."
run_output="$(nitro-cli run-enclave --cpu-count "$CPU_COUNT" --memory "$MEMORY_MB" --eif-path "$EIF_PATH")"
echo "$run_output"
enclave_id="$(echo "$run_output" | python3 -c 'import json,sys; print(json.load(sys.stdin)["EnclaveID"])')"

echo "run-enclave.sh: enclave $enclave_id is running."
echo "run-enclave.sh: waiting for the report collector to receive its one report..."
wait "$collector_pid"

echo "run-enclave.sh: report received — see $REPORTS_DIR/ for the file and the summary line printed above."
# cleanup (the EXIT trap) handles terminating the enclave and stopping the
# remaining helpers from here.

#!/usr/bin/env bash
# Standalone reproducibility check: rebuilds the EIF from the CURRENTLY
# CHECKED OUT source tree and compares the freshly measured PCR0 against
# the PCR0 committed in pcrs.json at the same tree. See REPRODUCE.md for
# the full walkthrough this script is one step of — in particular, this
# script does NOT check out a tag for you, or install Go/Docker/nitro-cli;
# it assumes you already have a Nitro Enclave-capable machine with those
# in place and are running this from the release tag you want to verify.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -f pcrs.json ]; then
	echo "verify-reproducibility.sh: no pcrs.json at repo root — nothing to compare against." >&2
	exit 2
fi

for tool in docker nitro-cli go python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "verify-reproducibility.sh: required tool '$tool' not found on PATH" >&2
		exit 1
	fi
done

SCANNER_VERSION="$(python3 -c "import json; print(json.load(open('pcrs.json')).get('scanner_version') or 'dev')")"
COMMITTED_PCR0="$(python3 -c "import json; print(json.load(open('pcrs.json'))['PCR0'])")"

echo "Rebuilding EIF for scanner version $SCANNER_VERSION..."
make eif SCANNER_VERSION="$SCANNER_VERSION"

REBUILT_PCR0="$(python3 -c "import json; print(json.load(open('scanner.eif.measurements.json'))['Measurements']['PCR0'])")"

echo
echo "Committed PCR0 (pcrs.json): $COMMITTED_PCR0"
echo "Rebuilt PCR0 (this machine): $REBUILT_PCR0"
echo

if [ "$COMMITTED_PCR0" = "$REBUILT_PCR0" ]; then
	echo "MATCH — this build reproduces the published enclave measurement."
	exit 0
fi

echo "MISMATCH — this build does NOT reproduce the published enclave measurement." >&2
echo "See REPRODUCE.md's troubleshooting section before concluding the release is compromised —" >&2
echo "check the Go version, base image digest, and nitro-cli version recorded in pcrs.json first." >&2
exit 1

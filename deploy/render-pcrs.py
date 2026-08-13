#!/usr/bin/env python3
"""Render pcrs.json from a nitro-cli build-enclave measurements JSON file.

Used by the release workflow (.github/workflows/release.yml) right after
`make eif`, and by anyone independently rebuilding the EIF per
REPRODUCE.md to compare their own PCR0 against the published value.

Usage:
    render-pcrs.py --measurements scanner.eif.measurements.json \\
        --commit <git-sha> --base-image-digest <digest> \\
        --scanner-version vX.Y.Z --output pcrs.json
"""
import argparse
import json
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--measurements", required=True, help="nitro-cli build-enclave JSON output file")
    parser.add_argument("--commit", required=True, help="git commit SHA the EIF was built from")
    parser.add_argument("--base-image-digest", required=True, help="resolved digest of the Dockerfile's FROM image")
    parser.add_argument("--scanner-version", required=True, help="immutable release tag, e.g. v1.2.3")
    parser.add_argument("--nitro-cli-version", required=True, help="output of `nitro-cli --version`")
    parser.add_argument("--go-version", required=True, help="output of `go version`")
    parser.add_argument("--output", required=True, help="path to write pcrs.json to")
    args = parser.parse_args()

    with open(args.measurements) as f:
        raw = json.load(f)

    measurements = raw.get("Measurements", raw)
    for field in ("PCR0", "PCR1", "PCR2"):
        if field not in measurements:
            print(f"render-pcrs.py: {args.measurements} has no {field} measurement", file=sys.stderr)
            return 1

    manifest = {
        "PCR0": measurements["PCR0"],
        "PCR1": measurements["PCR1"],
        "PCR2": measurements["PCR2"],
        "scanner_version": args.scanner_version,
        "commit_sha": args.commit,
        "base_image_digest": args.base_image_digest,
        "nitro_cli_version": args.nitro_cli_version,
        "go_version": args.go_version,
    }

    with open(args.output, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"render-pcrs.py: wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

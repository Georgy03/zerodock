# Reproducing a ZeroDock release

Every published scan report includes an attested `PCR0` measurement — a
SHA-384 hash that changes if a single byte of the enclave image differs.
`web/src/verify/pcr.ts` independently compares that attested PCR0 against
the `pcrs.json` published at the release tag named in the report's own
`scanner_version` field (see that file's header comment for why the tag
comes from attested content, not a hardcoded URL). This document is the
other half of that guarantee: how to rebuild the enclave image yourself
and confirm the published PCR0 is honest — that it really is what you get
from compiling the source in this repository, not something substituted
afterward.

## Time expectations

- **You've done this before, on hardware that's already set up:** 30–60
  minutes, almost all of it Docker layer caching and `nitro-cli
  build-enclave`'s own build time.
- **First time, starting from a bare AWS account:** budget most of a day.
  Provisioning a Nitro Enclave-capable EC2 instance, installing
  `nitro-cli`, and getting Docker and Go set up correctly is where the
  time actually goes — the build itself is the fast part.

Nothing here is fast because the process is complicated; it's slow
because a real hardware-isolated build environment isn't something most
people have sitting around.

## What you need

Nitro Enclave measurements depend on the exact bytes of the build
toolchain, not just the source code. **You must rebuild on real
Nitro-capable EC2 hardware** (e.g. an `m5.xlarge` or larger, with
`--enclave-options 'Enabled=true'` at launch) — PCR0 measured on a
non-Nitro machine, or with `nitro-cli`'s `--debug-mode` flag, will not
match a real published release, by design (debug mode deliberately zeros
the PCRs so nobody mistakes a debug build's measurement for a trusted
one).

Every release's `pcrs.json` (fetchable at
`https://raw.githubusercontent.com/Georgy03/zerodock/<tag>/pcrs.json`)
records the exact versions used for THAT release:

| Field                | Meaning                                                          |
| --------------------- | ----------------------------------------------------------------- |
| `PCR0` / `PCR1` / `PCR2` | The published enclave measurements                             |
| `scanner_version`     | The release tag this manifest belongs to                        |
| `commit_sha`          | The exact commit the EIF was built from                         |
| `base_image_digest`   | The immutable digest of `deploy/Dockerfile`'s `FROM` image       |
| `nitro_cli_version`   | Output of `nitro-cli --version` on the machine that built it     |
| `go_version`          | Output of `go version` on the machine that built it              |

Match all four tool versions exactly before rebuilding — a newer Go
patch release, a newer `nitro-cli`, or Docker Hub having moved the base
image tag to a new digest will all change PCR0, even though none of them
change a single line of this repository's source.

If you're rebuilding a specific past release, install the versions
`pcrs.json` names. If you're setting up fresh and don't care about
matching an old release exactly, current stable versions of Go, Docker,
and [`nitro-cli`](https://github.com/aws/aws-nitro-enclaves-cli) are
fine — just record what you used, the same way `pcrs.json` does.

## Steps

1. **Launch a Nitro Enclave-capable EC2 instance** and install
   `nitro-cli`, Docker, and Go (matching the versions in the `pcrs.json`
   for the tag you're verifying, per the table above). AWS's own
   [Nitro Enclaves User Guide](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html)
   covers `nitro-cli` installation; this repo does not duplicate that
   guide.

2. **Clone this repository and check out the exact tag** you're
   verifying — not `main`, a tag:

   ```bash
   git clone https://github.com/Georgy03/zerodock.git
   cd zerodock
   git checkout v1.2.3   # the tag named in the report's scanner_version
   ```

3. **Confirm your toolchain matches** what that tag's `pcrs.json`
   recorded:

   ```bash
   go version
   nitro-cli --version
   docker inspect --format='{{index .RepoDigests 0}}' golang:1.25-bookworm
   ```

   Compare each against the corresponding field in `pcrs.json`. A
   mismatch here is the first thing to fix — see Troubleshooting below
   before assuming anything is wrong with the release itself.

4. **Run the standalone verification script:**

   ```bash
   ./deploy/verify-reproducibility.sh
   ```

   This rebuilds the EIF exactly the way `make eif` does (Docker build →
   `nitro-cli build-enclave`), reads the PCR0 that build actually
   produced, and compares it against the `PCR0` already committed in
   `pcrs.json` at this tag. It prints `MATCH` or `MISMATCH` and exits
   non-zero on mismatch, so it's usable in a script or CI job as well as
   by hand.

   Under the hood this is just:

   ```bash
   make eif SCANNER_VERSION=v1.2.3
   # nitro-cli build-enclave prints PCR0/1/2 as JSON; compare PCR0
   # against pcrs.json's PCR0 by hand if you'd rather not use the script.
   ```

## What a mismatch means — and what it doesn't

A `MISMATCH` result means **this build**, on **this machine**, with
**these tool versions**, produced a different PCR0 than what's published.
Before concluding the published release is dishonest, rule out the
mundane explanations first — they are overwhelmingly the more likely
cause:

- **Toolchain drift.** A different Go patch version, a different
  `nitro-cli` version, or Docker Hub having moved a floating base-image
  tag to a new digest since the release was built will all change PCR0
  without changing any source code. Step 3 above exists specifically to
  catch this before you run the build.
- **Debug mode.** `nitro-cli build-enclave --debug-mode` produces
  zeroed PCRs, not real ones. `make eif` never passes this flag, but a
  hand-run `nitro-cli` command might.
- **A dirty tree.** `git status` should be clean after `git checkout
  v1.2.3` — any local modification, even an untracked file that Docker's
  build context happens to pick up, can change the measurement.

If none of those explain it — your toolchain versions match `pcrs.json`
exactly, the tree is clean, and you still get a different PCR0 — that is
a genuine finding worth reporting. Open an issue with your exact
`go version`, `nitro-cli --version`, and `docker inspect` output
alongside the mismatch.

## How this fits together with CI

`.github/workflows/release.yml` runs this same rebuild-and-compare on a
self-hosted, Nitro-capable runner for every tagged release, as a release
gate — a release whose CI-rebuilt PCR0 doesn't match its own committed
`pcrs.json` fails the workflow before a GitHub Release is ever created.
That gate catches an accidental mismatch at release time; it is not a
substitute for independently rebuilding yourself if you want to trust a
specific release rather than trust ZeroDock's CI.

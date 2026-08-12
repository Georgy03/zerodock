# ZeroDock

A cloud security scanner for AWS. The CLI runs read-only checks against an
AWS account and emits a single attested JSON report. Production builds run
inside AWS Nitro Enclaves — using the Nitro Security Module at `/dev/nsm` for
attestation and vsock (via the parent EC2 instance) for all networking, since
an enclave has neither a real network interface nor a reliable clock of its
own. Local development can opt into a software mock attester and a normal
network connection instead — see `--mock-attest` below.

## Layout

```
cmd/scanner/         CLI entrypoint: loads AWS config, runs every check, attests, prints JSON
cmd/api/              Week-5 backend server entrypoint (env-var configured; see "Backend" below)
internal/checks/      Check interface, the 11 checks, and the multi-region runner
internal/providers/   AWS-specific helpers (region enumeration, per-region config) with no
                       dependency on internal/checks — keeps a future second provider trivial
internal/attest/      Attester interface + mock and Nitro NSM implementations; low-level
                       COSE_Sign1 decode (Document, DecodeDocument, VerifySignature)
internal/verify/      Server-side attestation verification: signature, certificate chain,
                       and mock-vs-real-hardware-root policy — used by internal/api
internal/report/      The scan report's JSON shape, shared verbatim between cmd/scanner
                       (produces it) and internal/api (re-verifies it) — see that package's
                       comment for why they can't each define their own copy
internal/store/       Postgres persistence: append-only verdicts, buyer share tokens
internal/api/         HTTP handlers for the three endpoints below
internal/transport/   Networking: TCP (normal) vs vsock (inside an enclave) dialers, the
                       embedded-root-CA HTTP client, and the parent<->enclave credential/report handoff
migrations/            SQL schema + the REVOKE statements that make verdicts append-only
deploy/                Dockerfile, the vsock-proxy / credential-server / report-collector scripts
                       that run on the PARENT instance (never inside the enclave), and
                       run-enclave.sh, which orchestrates a full real run of all of the above
```

### Why the enclave boundary is already there

`internal/attest.Attester` is a one-method interface:

```go
type Attester interface {
    Attest(userData, nonce []byte) ([]byte, error)
}
```

`nonce` is caller-supplied, not generated inside the attester — that's what
real replay protection requires: only the party requesting the attestation
knows what nonce they picked, so a signed document echoing it back proves
freshness. `cmd/scanner` generates one random nonce per scan run today; a
future browser-side verifier would generate its own instead.

`MockAttester` implements the interface with a self-generated P-384 key and
a self-signed two-level cert chain. It produces a real COSE_Sign1 / ES384
document, CBOR-encoded, with the same field names and shapes as an actual
[AWS Nitro Enclave attestation document](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html):
`module_id`, `digest`, `timestamp`, `pcrs` (PCR0/1/2, 48-byte SHA-384
values), `certificate`, `cabundle`, `public_key`, `user_data`, `nonce`. The
PCR values are generated once, when the `MockAttester` is constructed, and
reused on every `Attest()` call — matching how a real PCR0 stays constant
for a given enclave image, so a verifier can meaningfully compare "the
PCR0 I saw today" against a previously published value.

`NSMAttester` uses `github.com/hf/nsm` to request a hardware-signed document
from `/dev/nsm`. The Linux implementation returns the raw COSE_Sign1 bytes;
other platforms provide a build-compatible stub with a clear unsupported
platform error. A browser-side verifier built against the mock's output only
needs to swap in the AWS Nitro root certificate for production documents;
the CBOR/COSE parsing code stays the same.

### Networking: an enclave has none of its own

A Nitro Enclave has no network interface, no IP address, and no DNS resolver
— vsock (a private channel to its own parent EC2 instance) is the only way
in or out. `internal/transport` hides that behind one small interface:

```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
```

`TCPDialer` wraps a normal `net.Dialer`, used outside an enclave.
`VsockDialer` looks the HOSTNAME it's asked to dial up in a fixed
`hostnameToVsockPort` table (`internal/transport/endpoints.go`) and dials the
parent instance (vsock context ID 3) on the matching port instead — an
unlisted hostname fails immediately with a clear error rather than hanging
forever, which is the single most likely way a new check silently breaks a
real enclave run. `cmd/scanner` picks which dialer to use with the same
`--mock-attest` flag that picks the attester, since the two always travel
together in practice.

Both dialers plug into one `*http.Client` (`transport.NewHTTPClient`) whose
`TLSClientConfig.RootCAs` is built ONLY from the four official Amazon Trust
Services root certificates, embedded into the binary at compile time via
`go:embed` (`internal/transport/rootcerts.go`) — never read from a file on
disk. That matters for two reasons: the `scratch`-based container image (see
`deploy/Dockerfile`) has no OS certificate store to read in the first place,
and baking the trust anchors into the binary means they're fixed the moment
the binary — and therefore PCR0 — is built, not swappable afterward by
modifying files on a running system.

**Credentials**: the parent EC2 instance already has real AWS credentials
via its own IAM instance role. `deploy/serve-credentials.py` (a reference
implementation; run on the PARENT, not in the enclave) fetches those from
IMDSv2 and, on every connection to vsock port 8200, sends them down as one
JSON blob. `transport.FetchCredentials` reads that blob once at enclave
startup and `cmd/scanner` wraps it in
`credentials.NewStaticCredentialsProvider`. **This is safe because TLS
terminates inside the enclave, not on the parent**: every vsock-proxy
process on the parent (`deploy/start-proxies.sh`) only ever relays opaque,
already-encrypted TLS bytes — it can hand the enclave credentials, but it
can never read a request the enclave makes with them, or alter a response
before the enclave sees it. Compromising the parent yields a copy of the
(temporary, expiring) credentials, never a way to observe or tamper with a
single AWS API call.

Three files have to agree on the same hostname↔port pairs by hand, because
vsock has no DNS or service discovery — a port number IS the address:
`internal/transport/endpoints.go` (what the enclave dials),
`deploy/vsock-proxy.yaml` (what the parent's proxies are allowed to forward
to), and `deploy/start-proxies.sh` (which starts one proxy per pair, on the
parent). **IAM is the one entry that's a trap**: it's a single GLOBAL AWS
endpoint (`iam.amazonaws.com`), not one per region like EC2/RDS/S3/CloudTrail/STS
— adding `iam.us-east-1.amazonaws.com` "to complete the pattern" adds a dead
entry nothing ever requests, while the real, unlisted hostname silently
hangs. All three files call this out explicitly at the IAM entry.

### Getting the report out: an enclave has no visible output either

Printing the finished report to stdout (`cmd/scanner` still does this) is
invisible to anyone unless the enclave was started with `--debug-mode` — and
`--debug-mode` zeroes out the PCR values, which defeats the entire point of
a production run. So the report's REAL delivery path is a third vsock
channel, symmetric to the credentials one but flowing the other direction:

- **Enclave → parent**: after producing the JSON report, `cmd/scanner`
  dials the parent on `transport.VsockPortReport` (8300), writes the whole
  report, and closes the connection (`transport.SendReport`). If the dial
  fails, `deliverReport` in `cmd/scanner/main.go` retries twice with a
  short backoff (500ms, then 1s) before giving up — and giving up returns
  an error that makes the program **exit non-zero**. A report that never
  reaches anyone is a failed run, not a silent success, the same principle
  behind `scope_verified`/`time_verified` above.
- **Parent side**: `deploy/collect-report.py` (a reference implementation)
  listens on port 8300, accepts exactly one connection, reads until EOF,
  saves the payload to a timestamped file under `./reports/`, and prints a
  one-line summary (scan ID, account, pass/fail/error counts) so you can
  eyeball the result without opening the file.

`deploy/run-enclave.sh` (invoked by `make run-enclave`) ties all three
parent-side helpers together for one full cycle: start the vsock-proxies,
the credential server, and the report collector; launch the enclave
without `--debug-mode`; wait for the collector to receive its one report
(that's the signal the scan actually finished); then tear the enclave and
every helper back down.

### Time: an enclave has no reliable clock either

An enclave's guest OS clock has no battery-backed real-time clock and no
network access to sync via NTP, so it can't be trusted — but the Nitro
hypervisor's own clock CAN be, and every attestation document's `timestamp`
field is stamped from it. `cmd/scanner` gets one throwaway attestation at
startup purely to read that trustworthy timestamp back out
(`attest.ExtractTimestamp`), then threads it through `Check.Run`'s `now`
parameter instead of letting checks call `time.Now()` themselves. Only
`aws.iam.key_age` actually uses it (a wrong clock could silently miscompute
a key's age), but the parameter exists on every check for interface
consistency. If the trustworthy timestamp can't be obtained, the report says
so explicitly via `time_verified: false` / `time_warning`, the same honesty
pattern used for `scope_verified` below, rather than silently falling back
to a guest clock that looks just as trustworthy as a real one.

## Setup

Requires Go 1.24+.

```bash
go mod download
```

AWS credentials come from the standard SDK v2 default chain (environment
variables, shared config/credentials files, SSO, an assumed role, an
instance/task role, etc.) — nothing AWS-specific needs to be passed on the
command line.

The scanning role needs read-only permissions for: EC2 (volumes, security
groups, regions), RDS (instances, snapshots, snapshot attributes), S3
(list buckets, get bucket location, public access block, bucket policy
status), IAM (account summary, list users, list access keys), CloudTrail
(describe trails, get trail status), and STS (get caller identity).
`ReadOnlyAccess` or `SecurityAudit` cover all of it.

## Run

```bash
go run ./cmd/scanner
```

Or build a binary:

```bash
go build -o zerodock ./cmd/scanner
./zerodock
```

By default the report is signed by the real Nitro NSM. On a development
machine, opt in to `MockAttester` explicitly:

```bash
go run ./cmd/scanner --mock-attest
```

`--regions` controls scan scope (default `us-east-1,us-east-2`):

```bash
go run ./cmd/scanner --mock-attest --regions us-east-1,eu-west-1
```

The report's `scanned_regions` is the intersection of what you asked for and
what AWS actually reports as enabled for the account — never broader than
either one, so the report can't claim coverage it didn't have.

### Organization-wide account coverage

When run from the AWS Organizations management account, the scanner calls
`DescribeOrganization` and paginates `ListAccounts` to establish the complete
account boundary. It attests `org_id`, `accounts_listed`, and
`accounts_scanned`; each control also retains a per-account result map. A
member enters `accounts_scanned` only after the dedicated
`ZeroDockScannerMemberRole` was assumed successfully. A missing role therefore
shows up as both a listed-vs-scanned coverage gap and explicit control errors.

AWS's exact `AWSOrganizationsNotInUseException` is the only condition treated
as a single-account estate. That produces `no_organization: true` and lists
the caller account in both account arrays. AccessDenied, a partial listing, or
another Organizations failure instead leaves organization verification false
and attests `organization_warning`; none is silently relabeled as "no org."

The scanner account's instance role needs its existing read-only audit access
plus these management-plane permissions. `deploy/deploy-stackset.sh` installs
the narrowly scoped `sts:AssumeRole` statement on `ZeroDockScannerRole` by
default (override the name with `SCANNER_ROLE_NAME`) because `SecurityAudit`
does not include it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/ZeroDockScannerMemberRole"
    }
  ]
}
```

Deploy the read-only member role from the management account after enabling
AWS Organizations trusted access for CloudFormation StackSets:

```bash
deploy/deploy-stackset.sh 123456789012  # scanner/management account ID
```

The script creates a `SERVICE_MANAGED` StackSet, targets the organization
root, and enables automatic deployment for accounts added later. The member
template attaches AWS `SecurityAudit`; it deliberately never requests
`OrganizationAccountAccessRole`, which is administrative. Service-managed
StackSets do not deploy into the management account itself, so its instance
role must already have the read-only permissions needed by the checks.

Build the Linux/amd64 container and EIF on a Nitro-enabled EC2 instance with
an immutable release tag sealed into the report:

```bash
make eif SCANNER_VERSION=v0.1.0
```

The `nitro-cli build-enclave` output includes PCR0, PCR1, and PCR2. The EIF
must be run without `--debug-mode` to retain measured (non-zero) PCR values.
Copy those measurements into `pcrs.json`, commit it without changing scanner
code, and create/push the exact same tag used above. The browser fetches:

```text
https://raw.githubusercontent.com/Georgy03/zerodock/v0.1.0/pcrs.json
```

It never reads measurements from `main`. The default `SCANNER_VERSION=dev`
keeps local builds convenient, but deliberately cannot pass the browser's
published-release PCR check.

To run it for real — proxies, credential server, report collector, the
enclave itself, then teardown, all in one step:

```bash
make run-enclave
```

(See "Getting the report out" above for what this actually orchestrates,
and `deploy/run-enclave.sh` for the implementation. This needs to run on
the parent instance, with docker, nitro-cli, and Nitro Enclave-capable
hardware — not on your laptop.)

To run the individual parent-side helpers by hand instead (e.g. while
debugging just one piece):

```bash
sudo deploy/start-proxies.sh &               # one vsock-proxy per allowlisted AWS endpoint
sudo python3 deploy/serve-credentials.py &   # serves this instance's IAM role creds over vsock
sudo python3 deploy/collect-report.py &      # saves the next report to ./reports/ and exits
```

### Output

A single JSON document to stdout:

```jsonc
{
  "scan_id": "…",
  "timestamp": "2026-08-11T12:00:00Z",
  "organization_verified": true,
  "org_id": "o-exampleorgid",
  "accounts_listed": ["111111111111", "222222222222"],
  "accounts_scanned": ["111111111111", "222222222222"],
  "account_id": "123456789012",
  "scope_verified": true,
  "time_verified": true,
  "requested_regions": ["us-east-1", "us-east-2"],
  "scanned_regions": ["us-east-1", "us-east-2"],
  "checks": {
    "aws.ebs.encryption": {
      "title": "Unencrypted EBS volumes",
      "tier": "provider_attested",
      "result": { "status": "fail", "findings": ["account 111111111111: us-east-1: unencrypted EBS volume vol-…"], "count": 4 },
      "accounts": {
        "111111111111": { "status": "fail", "findings": ["us-east-1: unencrypted EBS volume vol-…"], "count": 2 },
        "222222222222": { "status": "pass", "findings": null, "count": 2 }
      }
    },
    "…": "… one entry per registered check …"
  },
  "results_sha384": "…",
  "attestation": {
    "format": "COSE_Sign1/ES384 (mock attester)",
    "cose_sign1_base64": "…"
  }
}
```

`scope_verified` is `false` (with a `scope_warning` explaining why) whenever
`GetCallerIdentity` failed and the scan can't confirm which account it
covers — a report that can't say what it scanned isn't evidence.
`time_verified` is the same idea for `timestamp`: `false` (with
`time_warning`) whenever a hardware-attested clock couldn't be obtained.
`scanned_regions` is the same idea again, for scope breadth: it's the
intersection of `requested_regions` and whatever AWS reports as actually
enabled (`regions_warning` names anything requested but unavailable), so
the report can't silently claim to have scanned a region it never touched.
`accounts_listed` versus `accounts_scanned` applies that same honesty rule to
the organization boundary. All of these fields — along with `account_id` and
every aggregate and per-account check result — are
part of what gets hashed into `results_sha384` and sealed inside the
attestation, not just printed alongside it; see `attestedContent` in
`cmd/scanner/main.go` for why that distinction matters (a field left OUT of
the hash could be edited after signing without invalidating the
attestation).

## Checks

All checks are read-only and page through every API response fully.
Region-scoped checks (EBS, RDS, EC2 security groups) iterate every region
enabled for the account. IAM and CloudTrail checks are account-global by
nature (IAM has one root user and one set of access keys account-wide;
`DescribeTrails` already returns multi-region trails as shadow trails from
any single region) and are called once rather than once per region, to
avoid duplicate findings. S3 bucket listing is account-wide, with each
bucket's control-plane calls made against that bucket's actual region.

Tier says WHO is vouching for a finding, not how much work the check did:
`provider_attested` means AWS itself is asserting the underlying fact(s), no
matter how many of AWS's own API calls we had to combine to get there.
`actively_probed` (a real network challenge/response against the resource,
e.g. testing that `sslmode=disable` actually gets rejected) and `infra_only`
(cloud-API-verified envelope, unverified internals — e.g. a self-hosted
Postgres server's own disk encryption) don't apply to anything in this
build; every check here reads AWS-attested state. Those tiers start
mattering once self-hosted database checks are added.

| ID | Tier | What it flags |
|---|---|---|
| `aws.ebs.encryption` | provider_attested | Unencrypted EBS volumes |
| `aws.rds.encryption` | provider_attested | RDS instances with `StorageEncrypted=false` |
| `aws.s3.public` | provider_attested | Buckets without a fully-blocking public access block and either a public bucket policy or an incomplete block |
| `aws.rds.public_snapshots` | provider_attested | DB snapshots restorable by any AWS account |
| `aws.iam.root_mfa` | provider_attested | Root account without MFA (`GetAccountSummary`) |
| `aws.iam.key_age` | provider_attested | Active IAM access keys older than 90 days (inactive keys are skipped) |
| `aws.ec2.open_sg` | provider_attested | Security groups open to `0.0.0.0/0` / `::/0` on 22, 3389, 3306, 5432, or 27017 |
| `aws.rds.publicly_accessible` | provider_attested | RDS instances with `PubliclyAccessible=true` |
| `aws.cloudtrail.multiregion` | provider_attested | No active multi-region CloudTrail trail |
| `aws.rds.backup_retention` | provider_attested | RDS backup retention under 7 days |
| `aws.rds.deletion_protection` | provider_attested | RDS instances without deletion protection |

A permission error on any API call surfaces as `"status": "error"` with the
underlying AWS error code and message in `findings` — it is never treated
as a passing (or silently skipped) result. This matters for a network-
isolated enclave run in particular: every one of the 11 checks fails at its
first AWS API call before it can examine any resources, so all 11 correctly
report `error`/`count: 0` — never a silent `pass` from having examined zero
resources it never actually got network access to look at.

Every check's `Run` function also takes a `now time.Time` parameter (see
`Check.Run` in `internal/checks/types.go`) instead of calling `time.Now()`
itself — see "Time: an enclave has no reliable clock either" above. Only
`aws.iam.key_age` reads it.

## Backend (week 5)

`cmd/api` is a separate binary — an ordinary Go HTTP server backed by
Postgres — that receives scan reports from a running enclave, verifies them
independently (it does NOT just trust the submitter's word that a report is
genuine), and serves them back out to buyers via a share link.

### Endpoints

- **`POST /v1/verdicts`** — accepts a full `report.Report` JSON body (the
  exact thing `cmd/scanner` prints). Rejects the submission (4xx, nothing
  persisted) unless ALL of the following hold: `scope_verified` is `true`
  (a report that couldn't confirm which account it scanned is refused
  before anything else is even checked — it isn't evidence, no matter how
  well it's signed); the body decodes correctly; re-hashing the submitted
  `AttestedContent` matches the submission's own `results_sha384` (nothing
  was altered after the scanner computed that hash); the attached
  attestation's signature verifies and its certificate chain leads to a
  trusted root; and the attestation's own sealed `user_data` matches
  `results_sha384` too (the step that actually ties the SIGNED document to
  THESE results — without it, a genuinely-signed attestation from an
  unrelated scan could be attached to fabricated results and every other
  check would still pass). On success, returns `{"verdict_id", "scan_id",
  "token", "share_url", "mock"}` — `token` is this AWS account's
  buyer-facing share token (issued on its first verdict, reused after
  that; see the Database section below for what "issued" actually means
  today).
- **`GET /v1/share/{token}`** — the most recently ATTESTED verdict for that
  token (a buyer's bookmarked link always shows the latest scan of the same
  account). 404 for an unknown token or a known token with no verdicts yet;
  **410 Gone** for a token that existed and was explicitly revoked (see
  Database below) — distinct from 404 on purpose, since a client with a
  bookmarked link deserves "this was killed" rather than "this never
  existed".
- **`GET /v1/share/{token}/history`** — every verdict for that token, newest
  attested first (`?limit=` to cap the count; defaults and a hard ceiling
  are enforced server-side regardless). Same 404/410 rules as above.

Both GET responses include the raw attestation, base64-encoded
(`attestation.cose_sign1_base64`) — deliberately, not trimmed down to a
summary: the whole point of attesting in the first place is that a buyer's
own browser-side verifier can independently re-check it, not just trust
this server's word that it verified.

### Server-side verification (`internal/verify`)

Decodes the attestation (reusing `internal/attest`'s tagged/untagged
COSE_Sign1 handling — see the week-3/4 note on keeping MockAttester and NSM
byte-compatible; this is exactly why that invariant matters here too),
checks the signature, and walks the certificate chain to a self-signed
root using the standard library's own `x509` verification (evaluated at
the document's OWN attested timestamp, not wall-clock "now" — a verdict
might be verified long after it was produced, and a mock certificate's
short validity window shouldn't fail a legitimately-signed old document).

Whether that root is TRUSTED is the key policy decision: the real AWS Nitro
Enclaves root certificate is embedded the same way
`internal/transport/rootcerts.go` embeds the Amazon Trust Services roots —
downloaded from AWS's own repository, `go:embed`ded, never read from disk.
A chain that verifies but terminates somewhere else (inevitably a
`MockAttester` throwaway root — there's no single fixed "mock root" to pin,
since a fresh one is generated every time `NewMockAttester` runs) is
labeled `Mock: true`, and is only ACCEPTED if the server was started with
`ZERODOCK_ALLOW_MOCK_ATTESTATION=true` (development/staging only — this
should never be true wherever real buyer-facing verdicts are served).

**Authenticity is not freshness.** Evaluating the chain at the document's
own attested timestamp confirms the document is genuine — it deliberately
says nothing about whether that timestamp is *recent*. A two-year-old,
cryptographically perfect attestation verifies here with no warning. If
"how old is too old" ever needs to be enforced, that has to be a separate,
explicit check with its own window, owned by whoever renders a verdict for
a human (the eventual buyer page) — not smuggled into chain verification,
and not enforced at ingest by this API today. See the comments on
`verifyChain` in `internal/verify` and the package comment on
`internal/api` for the same point made where the code actually lives.

### Database (`internal/store`, `migrations/`)

Two tables: `share_links` (the real, explicit entity a `/v1/share/{token}`
URL resolves against — `token`, `vendor_id`, `account_id`, `label`,
`created_at`, `revoked_at`) and `verdicts` (append-only). `vendor_id` and
`label` exist for a real provisioning flow that doesn't exist yet; until
then, `CreateVerdict` auto-creates a link (those two columns left `NULL`)
the first time it sees a new `account_id` — a placeholder so `POST
/v1/verdicts` has somewhere to attach a token today, not the intended
long-term story. `revoked_at` lets a link be killed (see the 410 behavior
above) WITHOUT touching the verdicts underneath it — revoking a *link* and
erasing *evidence* are different operations, and only the latter is
supposed to be structurally impossible in this schema.

Append-only, for `verdicts` specifically, is enforced by POSTGRES ITSELF,
not application code:

```sql
GRANT SELECT, INSERT ON verdicts TO zerodock_app;
REVOKE UPDATE, DELETE ON verdicts FROM zerodock_app;
```

`zerodock_app` is the role the running server connects as — a bug, or even
a fully compromised API server process, still cannot alter or erase a
verdict once written, because Postgres refuses the query outright. This
was verified empirically, not just by reading the grant: running the exact
`UPDATE`/`DELETE` statements as `zerodock_app` against a real Postgres
instance returns `permission denied for table verdicts`.

`attestation_raw` (`BYTEA`) stores the exact bytes the enclave produced and
this server verified, verbatim, forever — never re-encoded or re-derived.
Everything else in a `verdicts` row is queryability/convenience derived
from that column, not a replacement for it.

### Configuration

`cmd/api` reads everything from environment variables:

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string, authenticating as `zerodock_app` |
| `LISTEN_ADDR` | no (default `:8080`) | HTTP listen address |
| `PUBLIC_BASE_URL` | no | Used only to build `share_url` in POST responses |
| `ZERODOCK_ALLOW_MOCK_ATTESTATION` | no (default `false`) | Accept verified-but-mock attestations |

```bash
# apply the schema once, as a privileged/owner role
psql "$ADMIN_DATABASE_URL" -f migrations/0001_init.sql
psql "$ADMIN_DATABASE_URL" -f migrations/0002_scanner_version.sql
psql "$ADMIN_DATABASE_URL" -f migrations/0003_organization_scope.sql

# run the server
DATABASE_URL="postgres://zerodock_app:...@host:5432/zerodock" go run ./cmd/api
```

## Tests

```bash
go test ./...
```

Covers:
- `internal/attest`: `MockAttester` produces a document that decodes as a
  valid COSE_Sign1 message, verifies against the ECDSA public key in its own
  embedded leaf certificate, whose leaf cert chains to the embedded root,
  with correctly-shaped and call-to-call-STABLE PCRs (not fresh random
  values per call — the property a real PCR0 needs), a caller-supplied
  (not attester-generated) nonce, and a matching `user_data`.
  `ExtractTimestamp` round-trips correctly against a document
  `MockAttester` just produced, and rejects garbage input.
- `internal/checks`: the pure decision logic behind `aws.ec2.open_sg`
  (port-range matching, `0.0.0.0/0`/`::/0` detection) and
  `aws.rds.public_snapshots` (public-restore attribute detection), plus a
  registration check for both, and the region-error-collapsing logic in
  the multi-region runner (many regions failing with the identical message
  become one finding, not one line per region).
- `internal/transport`: the hostname→vsock-port table has no duplicate
  ports and both region entries for every regional service (and exactly
  one, global entry for IAM — not a regional pair); an unlisted hostname
  fails `VsockDialer.DialContext` immediately with an error naming the
  host and pointing at `endpoints.go`, rather than hanging; the four
  embedded Amazon root certificates parse, are self-signed, and are
  marked as CAs; the parent→enclave credentials JSON is parsed and
  validated correctly (and rejected when malformed or incomplete); and a
  failed report delivery (`SendReport`, the enclave→parent direction)
  surfaces a clear, specific error rather than a bare one.
- `internal/verify`: a `MockAttester` document is rejected by default
  (`ErrMockNotAllowed`) and accepted only with `AllowMock: true`; a single
  flipped byte anywhere in a signed document breaks verification; garbage
  input fails cleanly.
- `internal/api`: every POST /v1/verdicts rejection path (`scope_verified:
  false`, tampered results hash, attestation `user_data` mismatch, mock
  rejected, duplicate `scan_id`, missing fields, invalid base64) against an
  in-memory fake store, plus the full success path, GET /v1/share
  returning the newest ATTESTED (not newest received) verdict, history
  returning all verdicts for a token, revoked tokens returning 410 on both
  GET endpoints, and unknown-token / store-failure 404s and 500s. The fake
  store is a real implementation of the same interface `*store.Store`
  satisfies — deliberately not a mock of individual method calls — so
  these tests exercise real handler logic, not assertions about what got
  called.
- `internal/store`: gated behind `ZERODOCK_TEST_DATABASE_URL` (skipped
  entirely if unset — there's no meaningful way to test real Postgres
  behavior without real Postgres). Point it at a database with
  all files in `migrations/` already applied, connecting as `zerodock_app`
  — exactly the restricted role the real server uses, not the migration
  owner role, so a query this package runs that role isn't actually
  permitted to run gets caught here rather than in production. Covers
  token issuance and reuse across an account's verdicts, duplicate
  `scan_id` rejection, "latest" meaning newest ATTESTED (not newest
  inserted), history ordering, revoking a share link leaving the verdicts
  under it untouched, and — the test that matters most —
  `TestVerdictsAreAppendOnly`, which runs real `UPDATE`/`DELETE`
  statements as `zerodock_app` against a real database and asserts
  Postgres itself refuses them.

The full backend was also exercised end-to-end by hand against a real,
throwaway Postgres container: applying the migration, confirming
`UPDATE`/`DELETE` on `verdicts` fail as `zerodock_app` but `INSERT`/`SELECT`
succeed, running `cmd/api` for real, and POSTing an actual
`MockAttester`-signed report to a live server — signature verification,
chain verification, hash matching, persistence, and both GET endpoints all
confirmed working against real, not stubbed, cryptography and a real
database.

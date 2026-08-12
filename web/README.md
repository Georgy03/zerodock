# ZeroDock buyer-facing verifier

React + TypeScript + Vite. Fetches a scan verdict from `GET
/v1/share/{token}` (see `internal/api` in the repo root) and verifies it
**entirely in this browser** — the server's word that it verified
server-side is never treated as sufficient on its own.

The headline is signed organization coverage, not a control score. It displays
`accounts_scanned / accounts_listed` (for example `18 / 18`) only when the
report attests successful Organizations enumeration. Explicit no-organization
reports show the verified `1 / 1` fallback. Enumeration failures and legacy
reports show "Coverage unknown" with the attested warning instead of inventing
a denominator.

## Why a second, independent verifier

`internal/api` already verifies every submission server-side
(`internal/verify`) before it's ever stored. This page exists anyway
because a buyer being asked to trust a security scan shouldn't have to
also trust that ZeroDock's own server didn't lie, get compromised, or
have a bug on the way from database to browser. Re-deriving the same
cryptographic conclusion independently, from the raw attestation bytes,
in the buyer's own browser, is what actually makes the "attested" claim
worth something to them.

## The six checks (`src/verify/`)

Run in order by `verifier.ts`, which stops at the first failure and
records every check — passed, failed, or "not run" — so the panel always
shows all six:

1. **`cose.ts`** — decodes CBOR, parses COSE_Sign1 (handles both the
   canonical CBOR-tag-18-wrapped form and the untagged form real AWS
   Nitro NSM documents use — the same two-form handling as
   `internal/attest/document.go` on the Go side).
2. **`chain.ts`** — validates the X.509 certificate chain, via `pkijs`,
   up to the AWS Nitro Enclaves root **embedded in this JS bundle at
   build time** (`rootcert.ts`, `?raw` import — never fetched at
   runtime; see that file for why that specific property is the whole
   point).
3. **`signature.ts`** — verifies the ES384 signature using the browser's
   native WebCrypto (`crypto.subtle`, ECDSA P-384 / SHA-384).
4. **`freshness.ts`** — checks the attested timestamp against a
   configurable window (`VITE_FRESHNESS_WINDOW_MS`) and confirms a
   correctly-shaped nonce is present. This is a DIFFERENT question from
   check 2's authenticity — see that file's header comment for why an
   old-but-genuine document is not the same problem as a forged one, and
   why freshness is deliberately a separate, explicit check rather than
   folded into chain validation.
5. **`hash.ts`** — recomputes SHA-384 over the fetched results and
   confirms it matches the attestation's own sealed `user_data` (proving
   THESE results are what was actually attested, not just that some
   attestation exists) — and separately cross-checks the API's own
   claimed `results_sha384` field for internal consistency.
6. **`pcr.ts`** — fetches `pcrs.json` directly from
   `raw.githubusercontent.com` (not from the ZeroDock API) and compares
   its published PCR0 to PCR0 inside the signed attestation payload.
   Signature verification proves AWS Nitro signed the document; this
   separate comparison proves the measured enclave was the published
   ZeroDock scanner image. The immutable Git tag comes from
   `scanner_version` inside the already-verified attested-content hash;
   only the repository origin is fixed in browser code. `main`, path
   traversal, arbitrary URLs, and non-release versions are rejected before
   any fetch.

**Fail closed** is the rule every file above answers to: any exception,
parse error, or unexpected shape from any check means the overall result
is `"failed"` — never `"verified"`. There is no code path that returns
`"verified"` except by every one of the six checks explicitly
succeeding (see `verifier.ts`'s header comment).

## Setup

```bash
npm install
cp .env.example .env   # point VITE_API_BASE_URL at your internal/api instance
npm run dev
```

With a verified share token open, the **Questionnaire autofill** section accepts
`.xlsx` or `.csv` and downloads a filled copy. The browser sends the file only
to the ZeroDock API behind that share link; the API processes it in memory and
does not store the questionnaire. Use
`../testdata/questionnaire-caiq-demo.csv` for a quick mixed pass/fail/human
review demo.

The API must be configured with `BUYER_BASE_URL` pointing at this browser UI.
That URL—not the private `/v1/share/...` JSON endpoint—is what exported
evidence cells contain.

Open `http://localhost:5173/?token=YOUR_TOKEN` (or `/YOUR_TOKEN` — the
last URL path segment works too if you don't want a query string).

## Tests

```bash
npm test        # vitest run
```

Runs entirely against **mock data** — `src/test/fixtures.ts` builds real,
correctly-signed COSE_Sign1 documents in TypeScript (fresh P-384 root +
leaf certs via WebCrypto and `pkijs`, the same shape
`internal/attest/mock.go` produces on the Go side) with no running Go
binary, enclave, or network needed. Because MockAttester and NSM
documents are byte-compatible by design (see the repo's week 2/3 notes),
this verifier was built and is tested entirely against local mock data,
and needs no changes to also handle real NSM-produced attestations.

Covers:

- **`verifier.test.ts`** — the full pipeline, both the "everything
  passes" case (verified against an injected test root — see below) and
  confirmation that a mock-signed document fails chain validation
  against the REAL embedded root with no override, proving there's no
  accidental "accept mock" path reachable from the running page.
- **`adversarial.test.ts`** — adversarial failure scenarios,
  asserted to render `"failed"`, never `"verified"`:
  - a **truncated document** (decode fails)
  - a **wrong-root chain** (signed by an unrelated CA)
  - a **tampered PCR0** (a byte inside the already-signed payload is
    flipped post-signing — the realistic form of "PCR0 doesn't match",
    since PCR0 only exists inside the signed payload; this correctly
    fails at the SIGNATURE check)
  - a **validly signed but unpublished PCR0**, which passes signature
    verification and fails the independent published-PCR0 check
  - a **stale timestamp** (outside the configured freshness window)
- **`hash.test.ts`** — dedicated coverage for the canonical-JSON
  replication of Go's `encoding/json.Marshal` (field order, `omitempty`,
  sorted map keys, `null` vs `[]` for empty findings, and HTML-escaping
  of `<`, `>`, `&` — see `hash.ts`'s header comment for why plain
  `JSON.stringify` can't be used directly here).

### On the test-only trust anchor override

`verifier.ts`'s `VerifyOptions.testOnlyTrustedRootDER` lets tests swap in
a locally-generated root instead of the real embedded AWS one — otherwise
no test fixture could ever reach `"verified"` without forging AWS's
actual private key. **The live page (`App.tsx`) never sets this field.**
Production code also throws immediately if the override is supplied while
`import.meta.env.PROD` is true. There is no URL parameter, environment
variable, or other reachable input that lets a real page load override the trust anchor; the parameter
exists solely for `verifier.test.ts`/`adversarial.test.ts` to exercise
the full "everything passes" path.

## Build

```bash
npm run build   # tsc -b && vite build -> dist/
```

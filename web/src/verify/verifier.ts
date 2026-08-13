// The orchestrator: runs all six client-side checks against a fetched
// GET /v1/share/{token} response and produces ONE overall verdict.
//
// FAIL CLOSED, the one rule every other file in this directory answers
// to: any exception, parse error, or unexpected shape from ANY of the
// six checks means the overall result is "failed" — never "verified".
// There is no code path in `verify()` below that can return status
// "verified" except by every one of the six checks explicitly
// succeeding. A bug that accidentally skips a check, or an unhandled
// exception type, fails the run rather than defaulting to a pass — see
// the try/catch around each step and the final `every()` check.
import { decodeCOSESign1, type DecodedDocument, COSEDecodeError } from "./cose";
import { validateChain, ChainValidationError } from "./chain";
import { verifySignature, SignatureVerificationError } from "./signature";
import { checkFreshness, FreshnessError, type FreshnessOptions } from "./freshness";
import { checkResultsHash, HashMismatchError, bytesToHex } from "./hash";
import { checkPublishedPCR0, PCRVerificationError } from "./pcr";
import { diffReports, type DiffEvent } from "./diff";
import type { ShareResponse } from "./types";

export type CheckName = "decode" | "chain" | "signature" | "freshness" | "hash" | "pcr0" | "diff";

export interface CheckOutcome {
  name: CheckName;
  label: string;
  passed: boolean;
  /** Human-readable description of what this check actually did, for the verification panel. */
  detail: string;
}

export interface VerificationResult {
  status: "verified" | "failed";
  checks: CheckOutcome[];
  document?: DecodedDocument;
  /** Present only if status === "verified": the leaf certificate's identity, for display. */
  leafSubject?: string;
  rootSubject?: string;
}

export interface VerifyOptions {
  freshnessWindowMs: number;
  /** Injectable for tests. */
  now?: () => Date;
  /**
   * TEST-ONLY trust anchor override, passed straight through to
   * chain.validateChain. App.tsx — the only real caller in this
   * application — never sets this, so the live page always validates
   * against the real embedded AWS Nitro root. Exists purely so this
   * orchestrator's tests can exercise a full "everything passes" run
   * against a locally-generated test chain (see src/test/fixtures.ts),
   * without needing to forge a signature from AWS's actual private key.
   */
  testOnlyTrustedRootDER?: Uint8Array;

  /**
   * Skips the freshness check (window + nonce shape stays unevaluated),
   * marking it passed with an explanatory detail instead of running it.
   * Freshness answers "is this recent enough to be the CURRENT state" —
   * exactly the wrong question for a historical entry being verified for
   * scope-drift comparison (verify/scope.ts) or the scope history
   * timeline, where an entry being months old is expected, not
   * suspicious. Every other check (chain, signature, hash, PCR0) still
   * runs at full strength — this only narrows what "verified" means for
   * a historical entry to "authentic", not "current".
   */
  skipFreshness?: boolean;
}

/**
 * Computes a change set only after the caller has independently verified both
 * snapshots with verifyShareResponse. This is the seventh buyer-page check:
 * it does not accept an API-supplied diff, and any unexpected snapshot shape
 * becomes a failed check with no changes rendered.
 */
export function recomputeAttestedDiff(previous: ShareResponse, current: ShareResponse): { events: DiffEvent[]; check: CheckOutcome } {
  try {
    const events = diffReports(previous, current);
    return {
      events,
      check: {
        name: "diff",
        label: "Recompute changes from attested snapshots",
        passed: true,
        detail: `Locally compared ${events.length} transition${events.length === 1 ? "" : "s"} from two independently verified attested snapshots; the API did not supply this diff.`,
      },
    };
  } catch (err) {
    return {
      events: [],
      check: {
        name: "diff",
        label: "Recompute changes from attested snapshots",
        passed: false,
        detail: `Diff was not rendered: ${err instanceof Error ? err.message : String(err)}`,
      },
    };
  }
}

/**
 * Runs the six checks in order, stopping at the first failure (later
 * checks generally depend on earlier ones having succeeded — e.g.
 * signature verification needs a successfully decoded document). Every
 * check that WAS attempted, pass or fail, is recorded in the result;
 * checks after the first failure are recorded as not-run/skipped rather
 * than silently absent, so the panel always shows all six entries.
 */
export async function verifyShareResponse(resp: ShareResponse, opts: VerifyOptions): Promise<VerificationResult> {
  // This override makes cryptographic fixtures possible, but it must never
  // become a production trust-anchor switch. Vite replaces PROD with a
  // compile-time boolean, so production builds retain an unconditional throw
  // on every path that attempts to provide the test-only root.
  if (import.meta.env.PROD && opts.testOnlyTrustedRootDER) {
    throw new Error("testOnlyTrustedRootDER is disabled in production builds");
  }

  const checks: CheckOutcome[] = [];
  let document: DecodedDocument | undefined;
  let leafSubject: string | undefined;
  let rootSubject: string | undefined;

  // --- Check 1: decode CBOR / parse COSE_Sign1 ---
  try {
    const raw = base64ToBytes(resp.attestation.cose_sign1_base64);
    document = decodeCOSESign1(raw);
    checks.push({
      name: "decode",
      label: "Decode attestation document",
      passed: true,
      detail: `Parsed a valid COSE_Sign1 structure (module ${document.payload.module_id}); handles both CBOR tag 18 and untagged encodings.`,
    });
  } catch (err) {
    checks.push(failedOutcome("decode", "Decode attestation document", err, COSEDecodeError));
    return closedResult(checks);
  }

  // --- Check 2: X.509 chain to the embedded AWS Nitro root ---
  let leafPublicKeySPKI: ArrayBuffer | undefined;
  try {
    const attestedAt = new Date(document.payload.timestamp);
    const result = opts.testOnlyTrustedRootDER
      ? await validateChain(document.payload.certificate, document.payload.cabundle, attestedAt, opts.testOnlyTrustedRootDER)
      : await validateChain(document.payload.certificate, document.payload.cabundle, attestedAt);
    leafSubject = certificateSubject(result.leaf);
    rootSubject = certificateSubject(result.root);
    leafPublicKeySPKI = result.leaf.subjectPublicKeyInfo.toSchema().toBER(false);
    checks.push({
      name: "chain",
      label: "Validate certificate chain",
      passed: true,
      detail: "The document's leaf certificate chains through its AWS-issued bundle to the embedded AWS Nitro Enclaves root, evaluated at the document's attested time.",
    });
  } catch (err) {
    checks.push(failedOutcome("chain", "Validate certificate chain", err, ChainValidationError));
    return closedResult(checks, document);
  }

  // --- Check 3: ES384 signature via WebCrypto ---
  try {
    await verifySignature(document, leafPublicKeySPKI);
    checks.push({
      name: "signature",
      label: "Verify ES384 signature",
      passed: true,
      detail: "ECDSA P-384 / SHA-384 signature verified via WebCrypto against the leaf certificate's public key.",
    });
  } catch (err) {
    checks.push(failedOutcome("signature", "Verify ES384 signature", err, SignatureVerificationError));
    return closedResult(checks, document, leafSubject, rootSubject);
  }

  // --- Check 4: freshness (timestamp window + nonce) ---
  if (opts.skipFreshness) {
    checks.push({
      name: "freshness",
      label: "Check freshness",
      passed: true,
      detail: "Skipped: this entry is being verified as historical evidence (authenticity only), not as the current state.",
    });
  } else {
    try {
      const freshness = checkFreshness(document, { windowMs: opts.freshnessWindowMs, now: opts.now } satisfies FreshnessOptions);
      checks.push({
        name: "freshness",
        label: "Check freshness",
        passed: true,
        detail: `Attested ${Math.round(freshness.ageMs / 1000)}s ago, within the ${Math.round(freshness.windowMs / 1000)}s window; carries a ${freshness.nonceLength}-byte nonce.`,
      });
    } catch (err) {
      checks.push(failedOutcome("freshness", "Check freshness", err, FreshnessError));
      return closedResult(checks, document, leafSubject, rootSubject);
    }
  }

  // --- Check 5: recompute SHA-384 over results, compare to user_data ---
  try {
    const hashResult = await checkResultsHash(resp, document.payload.user_data);
    checks.push({
      name: "hash",
      label: "Recompute results hash",
      passed: true,
      detail: `Recomputed SHA-384 (${hashResult.computedHex.slice(0, 16)}...) matches the attestation's sealed user_data and the API's results_sha384.`,
    });
  } catch (err) {
    checks.push(failedOutcome("hash", "Recompute results hash", err, HashMismatchError));
    return closedResult(checks, document, leafSubject, rootSubject);
  }

  // --- Check 6: compare signed PCR0 to the independently published release ---
  try {
    // scanner_version is part of the content whose hash was verified in the
    // previous step. The API therefore cannot redirect this lookup to a more
    // convenient release tag without breaking the attestation's user_data.
    const pcr = await checkPublishedPCR0(document.payload.pcrs.get(0), resp.scanner_version);
    checks.push({
      name: "pcr0",
      label: "Match published scanner PCR0",
      passed: true,
      detail: `Signed PCR0 ${pcr.actualPCR0.slice(0, 16)}... matches ${resp.scanner_version}'s release measurement fetched independently from raw.githubusercontent.com.`,
    });
  } catch (err) {
    checks.push(failedOutcome("pcr0", "Match published scanner PCR0", err, PCRVerificationError));
    return closedResult(checks, document, leafSubject, rootSubject);
  }

  // Only reachable if every check above pushed passed: true.
  if (!checks.every((c) => c.passed)) {
    // Defensive: should be unreachable given the early returns above, but
    // "fail closed" means this codepath does not get to assume that.
    return closedResult(checks, document, leafSubject, rootSubject);
  }

  return { status: "verified", checks, document, leafSubject, rootSubject };
}

function failedOutcome(name: CheckName, label: string, err: unknown, _expectedType: unknown): CheckOutcome {
  const message = err instanceof Error ? err.message : String(err);
  return { name, label, passed: false, detail: message };
}

/** Fills in any checks that weren't reached with an explicit "not run" entry, then returns a failed result. */
function closedResult(
  checks: CheckOutcome[],
  document?: DecodedDocument,
  leafSubject?: string,
  rootSubject?: string,
): VerificationResult {
  const order: { name: CheckName; label: string }[] = [
    { name: "decode", label: "Decode attestation document" },
    { name: "chain", label: "Validate certificate chain" },
    { name: "signature", label: "Verify ES384 signature" },
    { name: "freshness", label: "Check freshness" },
    { name: "hash", label: "Recompute results hash" },
    { name: "pcr0", label: "Match published scanner PCR0" },
  ];
  const seen = new Set(checks.map((c) => c.name));
  const withSkipped = [...checks];
  for (const { name, label } of order) {
    if (!seen.has(name)) {
      withSkipped.push({ name, label, passed: false, detail: "Not run — an earlier check failed." });
    }
  }
  return { status: "failed", checks: withSkipped, document, leafSubject, rootSubject };
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function certificateSubject(cert: { subject: { typesAndValues: { type: string; value: { valueBlock: { value: string } } }[] } }): string {
  try {
    return cert.subject.typesAndValues.map((tv) => tv.value.valueBlock.value).join(", ");
  } catch {
    return "(unavailable)";
  }
}

export { bytesToHex };

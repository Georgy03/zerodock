// Freshness check: is the document's own attested timestamp within an
// acceptable window, and does it carry a nonce at all.
//
// IMPORTANT SCOPE NOTE, matching internal/verify's own comment on this
// exact distinction (Go side: verifyChain's big comment; see also
// internal/api's package comment): this is NOT the same question as
// "is the signature/chain authentic". A perfectly genuine, correctly
// signed attestation can still be OLD — evaluating validity at its own
// timestamp (chain.ts) proves it's real, not that it's current. That's
// why freshness is its own separate, explicit check with its own
// configurable window, rather than folded into chain validation.
//
// A SECOND, narrower scope note specific to THIS page: GET
// /v1/share/{token} returns a STORED, historical verdict — not a live
// challenge-response with the enclave. There is no nonce this page
// itself generated moments ago to compare the document's nonce against
// (that would require a live round trip to a running enclave, which a
// share link intentionally does not do). So the "nonce echo" check here
// is necessarily a STRUCTURAL one — the document carries a present,
// correctly-shaped nonce, proving the attester's own freshness
// machinery ran as designed — not a live replay-protection guarantee for
// THIS page view. That distinction is real and worth remembering before
// treating this check as more than it is.
import type { DecodedDocument } from "./cose";

export class FreshnessError extends Error {}

/** Nonces this scanner generates are always 32 random bytes — see cmd/scanner/main.go. */
const EXPECTED_NONCE_LENGTH = 32;

export interface FreshnessOptions {
  /** How far in the past an attested timestamp may be and still count as "fresh", in milliseconds. */
  windowMs: number;
  /** Injectable for tests; defaults to the real current time. */
  now?: () => Date;
}

export interface FreshnessResult {
  attestedAt: Date;
  ageMs: number;
  windowMs: number;
  nonceLength: number;
}

/**
 * Checks doc.payload.timestamp against opts.windowMs (relative to
 * opts.now(), or real "now" if not supplied), and confirms a
 * correctly-shaped nonce is present. Throws FreshnessError if either
 * check fails.
 */
export function checkFreshness(doc: DecodedDocument, opts: FreshnessOptions): FreshnessResult {
  const attestedAt = new Date(doc.payload.timestamp);
  if (Number.isNaN(attestedAt.getTime())) {
    throw new FreshnessError(`document timestamp is not a valid time: ${doc.payload.timestamp}`);
  }

  const now = (opts.now ?? (() => new Date()))();
  const ageMs = now.getTime() - attestedAt.getTime();

  if (ageMs < 0) {
    // A document attested in the future relative to our clock is exactly
    // as suspicious as one that's stale — either the document is wrong,
    // or the verifying machine's clock is, and neither is a case to wave
    // through silently.
    throw new FreshnessError(
      `document is attested ${Math.abs(ageMs)}ms in the future relative to the local clock`,
    );
  }
  if (ageMs > opts.windowMs) {
    throw new FreshnessError(
      `document was attested ${Math.round(ageMs / 1000)}s ago, outside the ${Math.round(opts.windowMs / 1000)}s freshness window`,
    );
  }

  const nonce = doc.payload.nonce;
  if (!nonce || nonce.length === 0) {
    throw new FreshnessError("document has no nonce");
  }
  if (nonce.length !== EXPECTED_NONCE_LENGTH) {
    throw new FreshnessError(`nonce is ${nonce.length} bytes, want ${EXPECTED_NONCE_LENGTH}`);
  }

  return { attestedAt, ageMs, windowMs: opts.windowMs, nonceLength: nonce.length };
}

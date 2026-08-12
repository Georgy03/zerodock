// Verifies the COSE_Sign1 ES384 signature using the browser's native
// WebCrypto (crypto.subtle) — no crypto library needed for this part at
// all, since ECDSA P-384 / SHA-384 is a standard WebCrypto algorithm.
//
// This mirrors internal/attest.VerifySignature on the Go side: the same
// algorithm (ES384 = ECDSA using the P-384 curve and SHA-384), verifying
// over the same bytes (the CBOR-encoded Sig_structure — see
// cose.buildSigStructure), against the public key taken from the LEAF
// CERTIFICATE embedded in the document itself (not a separately supplied
// key) — exactly like the Go side deliberately does not decide whether to
// trust that key; chain.ts is what decides that.
import type { DecodedDocument } from "./cose";
import { buildSigStructure } from "./cose";

export class SignatureVerificationError extends Error {}

/**
 * Imports leafPublicKeySPKI as a WebCrypto ECDSA P-384 public key and
 * verifies doc's signature against it. Throws SignatureVerificationError
 * if the key is malformed, the algorithm doesn't match, or the signature
 * simply does not verify (WebCrypto's verify() returning false is treated
 * identically to a thrown parse error — both are "not verified", full
 * stop, per fail-closed).
 */
export async function verifySignature(doc: DecodedDocument, leafPublicKeySPKI: ArrayBuffer): Promise<void> {
  // P-384 has 48-byte coordinates, so a COSE ES384 signature must be exactly
  // 48-byte r followed by 48-byte s. Rejecting any other size here prevents a
  // future refactor from silently passing a DER-wrapped ECDSA signature to
  // WebCrypto (whose browser API expects this raw IEEE P1363 form).
  if (doc.signature.length !== 96) {
    throw new SignatureVerificationError(
      `ES384 signature must be raw 96-byte r||s, got ${doc.signature.length} bytes`,
    );
  }

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "spki",
      leafPublicKeySPKI,
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
  } catch (err) {
    throw new SignatureVerificationError(`import leaf public key as ECDSA P-384: ${(err as Error).message}`);
  }

  const message = buildSigStructure(doc);

  let valid: boolean;
  try {
    // WebCrypto's ECDSA verify expects the signature as raw r||s
    // concatenation (IEEE P1363 format) — which is exactly the format
    // COSE signatures already use, so doc.signature's bytes are passed
    // straight through with no re-encoding (just copied into a
    // plain-ArrayBuffer-backed view — cborg's decoded byte strings can be
    // views over a larger shared buffer, which WebCrypto's stricter
    // BufferSource typing doesn't accept directly).
    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      key,
      new Uint8Array(doc.signature),
      new Uint8Array(message),
    );
  } catch (err) {
    throw new SignatureVerificationError(`verify: ${(err as Error).message}`);
  }

  if (!valid) {
    throw new SignatureVerificationError("ES384 signature does not verify against the document's leaf certificate");
  }
}

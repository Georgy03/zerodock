// Decodes a COSE_Sign1 attestation document — the exact same bytes
// internal/attest.MockAttester.Attest / NSMAttester.Attest produce on the
// Go side, and the exact same two on-wire shapes internal/attest/document.go's
// parseCOSESign1 accepts:
//   - CBOR tag 18 wrapped (the canonical form emitted by both AWS Nitro NSM
//     and MockAttester)
//   - untagged (the bare four-element Sign1 array, accepted for backwards
//     compatibility with older MockAttester documents)
//
// This is the browser half of the SAME parsing logic — mirroring it here,
// rather than reinventing a different decode strategy, is what "keep the
// invariant" (week 3/4: MockAttester and NSM must stay byte-compatible)
// buys us: this file was built and tested entirely against MockAttester
// output, and needs no changes to also accept real NSM documents.
import { decode, encode } from "cborg";

/** A decoded but NOT YET VERIFIED attestation document. */
export interface DecodedDocument {
  /** Raw protected-header bytes, EXACTLY as signed — needed verbatim for signature.ts. */
  protectedHeaderBytes: Uint8Array;
  /** Decoded protected header map (e.g. alg). */
  protectedHeader: Map<unknown, unknown>;
  /** Raw payload bytes, EXACTLY as signed — needed verbatim for signature.ts. */
  payloadBytes: Uint8Array;
  /** The decoded document payload (module_id, pcrs, certificate, ...). */
  payload: AttestationPayload;
  /** Raw ECDSA signature bytes: raw r||s concatenation (COSE's format, not DER). */
  signature: Uint8Array;
}

/** The CBOR map carried as the COSE_Sign1 payload — see internal/attest.Document. */
export interface AttestationPayload {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  public_key: Uint8Array | null;
  user_data: Uint8Array | null;
  nonce: Uint8Array | null;
}

export class COSEDecodeError extends Error {}

/**
 * Decodes raw attestation document bytes into a DecodedDocument. Throws
 * COSEDecodeError on anything malformed — callers (verifier.ts) treat any
 * thrown error as a failed check, per "fail closed": there is no
 * "probably fine" partial-decode result.
 */
export function decodeCOSESign1(bytes: Uint8Array): DecodedDocument {
  let outer: unknown;
  try {
    // Registering a decoder for tag 18 that just returns its contents
    // directly handles BOTH wire forms with one decode call: a
    // tag-18-wrapped document decodes straight through to the inner
    // 4-element array, and an untagged document (no tag byte present at
    // all) decodes to that same array on its own — there is nothing to
    // unwrap, so the same code path just falls through. useMaps: true
    // because the array's "unprotected" element is a genuine CBOR map
    // that can carry integer COSE header labels (e.g. alg = 1) — cborg's
    // default plain-object decoding rejects non-string map keys outright.
    outer = decode(bytes, { tags: { 18: (decodeInner) => decodeInner() }, useMaps: true });
  } catch (err) {
    throw new COSEDecodeError(`decode COSE_Sign1 CBOR: ${(err as Error).message}`);
  }

  if (!Array.isArray(outer) || outer.length !== 4) {
    throw new COSEDecodeError(
      `expected a 4-element COSE_Sign1 array, got ${Array.isArray(outer) ? `array of length ${outer.length}` : typeof outer}`,
    );
  }
  const [protectedBytes, , payloadBytes, signature] = outer as [
    Uint8Array,
    Map<unknown, unknown> | undefined,
    Uint8Array,
    Uint8Array,
  ];

  if (!(protectedBytes instanceof Uint8Array)) {
    throw new COSEDecodeError("COSE_Sign1 protected header is not a byte string");
  }
  if (!(payloadBytes instanceof Uint8Array)) {
    throw new COSEDecodeError("COSE_Sign1 payload is not a byte string");
  }
  if (!(signature instanceof Uint8Array)) {
    throw new COSEDecodeError("COSE_Sign1 signature is not a byte string");
  }

  let protectedHeader: Map<unknown, unknown>;
  try {
    // An empty protected header serializes as a zero-length byte string
    // (see go-cose's Headers.MarshalProtected), which is valid and just
    // means "no protected header parameters" — treat it as an empty map
    // rather than trying to CBOR-decode zero bytes.
    protectedHeader = protectedBytes.length === 0 ? new Map() : (decode(protectedBytes, { useMaps: true }) as Map<unknown, unknown>);
  } catch (err) {
    throw new COSEDecodeError(`decode protected header: ${(err as Error).message}`);
  }

  let rawPayload: unknown;
  try {
    rawPayload = decode(payloadBytes, { useMaps: true });
  } catch (err) {
    throw new COSEDecodeError(`decode attestation document payload: ${(err as Error).message}`);
  }
  const payload = parseAttestationPayload(rawPayload);

  return { protectedHeaderBytes: protectedBytes, protectedHeader, payloadBytes, payload, signature };
}

function parseAttestationPayload(raw: unknown): AttestationPayload {
  if (!(raw instanceof Map)) {
    throw new COSEDecodeError("attestation document payload is not a CBOR map");
  }
  const get = (key: string) => raw.get(key);

  const moduleId = get("module_id");
  const digest = get("digest");
  const timestamp = get("timestamp");
  const pcrs = get("pcrs");
  const certificate = get("certificate");
  const cabundle = get("cabundle");

  if (typeof moduleId !== "string") throw new COSEDecodeError("module_id is missing or not a string");
  if (typeof digest !== "string") throw new COSEDecodeError("digest is missing or not a string");
  if (typeof timestamp !== "number" && typeof timestamp !== "bigint") {
    throw new COSEDecodeError("timestamp is missing or not a number");
  }
  if (!(pcrs instanceof Map)) throw new COSEDecodeError("pcrs is missing or not a map");
  if (!(certificate instanceof Uint8Array)) throw new COSEDecodeError("certificate is missing or not a byte string");
  if (!Array.isArray(cabundle) || cabundle.some((c) => !(c instanceof Uint8Array))) {
    throw new COSEDecodeError("cabundle is missing or not an array of byte strings");
  }

  return {
    module_id: moduleId,
    digest,
    timestamp: Number(timestamp),
    pcrs: pcrs as Map<number, Uint8Array>,
    certificate,
    cabundle: cabundle as Uint8Array[],
    public_key: (get("public_key") as Uint8Array | undefined) ?? null,
    user_data: (get("user_data") as Uint8Array | undefined) ?? null,
    nonce: (get("nonce") as Uint8Array | undefined) ?? null,
  };
}

/**
 * Builds the exact bytes that were signed: the CBOR-encoded COSE
 * "Sig_structure" (RFC 8152 §4.4) —
 * ["Signature1", protected_bytes, external_aad(empty), payload_bytes].
 * Both protected_bytes and payload_bytes MUST be the original raw bytes
 * from the document, not a re-encoding of the decoded values — CBOR
 * doesn't guarantee a unique re-encoding matches the original bytes in
 * general (it happens to for the simple types used here, but using the
 * raw bytes removes any doubt and matches what go-cose signs over).
 */
export function buildSigStructure(doc: DecodedDocument): Uint8Array {
  const externalAAD = new Uint8Array(0);
  return encode(["Signature1", doc.protectedHeaderBytes, externalAAD, doc.payloadBytes]);
}

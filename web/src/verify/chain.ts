// Validates the attestation's certificate chain (leaf -> ... -> a
// self-signed root, via the document's own cabundle) up to the EMBEDDED
// AWS Nitro root (see rootcert.ts) — the browser-side mirror of
// internal/verify.verifyChain on the Go side. Same approach, same
// reasoning: use a real X.509 chain-validation engine (there, the Go
// standard library's crypto/x509; here, pkijs) instead of hand-rolling
// pairwise signature checks, and evaluate validity at the document's OWN
// attested timestamp rather than wall-clock "now" — see the big comment
// on that Go function for why (a verdict examined long after it was
// produced shouldn't fail chain validation purely because a short-lived
// certificate's window has since passed).
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { awsNitroRootDER } from "./rootcert";

let engineReady = false;

/** Registers pkijs's WebCrypto engine, once, lazily. */
function ensureEngine(): void {
  if (engineReady) return;
  const engine = new pkijs.CryptoEngine({ name: "browser-webcrypto", crypto: crypto, subtle: crypto.subtle });
  // pkijs's ICryptoEngine type and the DOM lib's SubtleCrypto type have
  // drifted slightly (newer experimental algorithm overloads on
  // generateKey), which trips up structural type-checking here even
  // though CryptoEngine is pkijs's own, correct implementation of this
  // exact interface — a type-system false positive, not a real mismatch.
  pkijs.setEngine("browser-webcrypto", engine as unknown as pkijs.ICryptoEngine);
  engineReady = true;
}

export class ChainValidationError extends Error {}

export interface ChainValidationResult {
  /** The exact end-entity certificate supplied by the attestation payload. */
  leaf: pkijs.Certificate;
  /** The self-signed root the chain actually terminated at. */
  root: pkijs.Certificate;
  /** The path PKI.js resolved. Do not assume its first entry is the leaf. */
  path: pkijs.Certificate[];
}

/**
 * Parses leafDER and each cert in cabundleDER, and validates that the
 * leaf chains up to a self-signed root that is BYTE-IDENTICAL to the
 * trusted root — evaluated at checkDate (the document's own attested
 * timestamp). Throws ChainValidationError on any failure: malformed
 * certificate, broken chain, or a chain that validates but terminates at
 * some OTHER root.
 *
 * trustedRootDER defaults to the embedded AWS Nitro root (rootcert.ts) —
 * that default is what every real code path in this app (verifier.ts,
 * and therefore App.tsx) uses, with no way for a URL, query string, or
 * any other piece of untrusted input to change it. The parameter exists
 * ONLY so tests can validate this function's logic against a
 * locally-generated test root (see src/test/fixtures.ts) without needing
 * to forge a signature from AWS's actual private key — there is no
 * equivalent "AllowMock" escape hatch reachable from the running page,
 * unlike the backend's server-side AllowMock flag: a buyer-facing page
 * has no legitimate reason to ever display an unverified mock scan as if
 * it were hardware-backed.
 */
export async function validateChain(
  leafDER: Uint8Array,
  cabundleDER: Uint8Array[],
  checkDate: Date,
  trustedRootDER: Uint8Array = new Uint8Array(awsNitroRootDER()),
): Promise<ChainValidationResult> {
  ensureEngine();

  const leaf = parseCertificate(leafDER, "leaf certificate");
  const intermediatesAndRoots = cabundleDER.map((der, i) => parseCertificate(der, `cabundle[${i}]`));
  const trustedRoot = parseCertificate(trustedRootDER, "trusted root");

  const chainEngine = new pkijs.CertificateChainValidationEngine({
    certs: [leaf, ...intermediatesAndRoots],
    trustedCerts: [trustedRoot],
    checkDate,
  });

  const verifyResult = await chainEngine.verify();
  if (!verifyResult.result) {
    throw new ChainValidationError(
      `certificate chain does not validate against the trusted root: ${verifyResult.resultMessage || `code ${verifyResult.resultCode}`}`,
    );
  }

  const path = verifyResult.certificatePath ?? [];
  const root = path[path.length - 1];
  if (!root || !sameCertificate(root, trustedRoot)) {
    // Belt-and-suspenders: pkijs's trustedCerts option should make this
    // unreachable (verify() should only succeed against a cert actually
    // in trustedCerts), but we do NOT rely on that alone — explicitly
    // re-confirming the terminal certificate is byte-identical to the
    // trusted root is what actually enforces "never trust an unknown
    // root" rather than trusting pkijs's internal bookkeeping to have
    // done so.
    throw new ChainValidationError("chain validated but did not terminate at the trusted root");
  }

  // Return `leaf` directly from the certificate we parsed above. PKI.js's
  // certificatePath ordering/content differs with chain shape: for the real
  // Nitro chain it begins at an intermediate and does not include the supplied
  // end-entity certificate, while our two-certificate mock happens to put the
  // leaf first. Inferring the signing key from path[0] therefore passed every
  // mock test and failed only on hardware documents.
  return { leaf, root, path };
}

function parseCertificate(der: Uint8Array, label: string): pkijs.Certificate {
  let asn1;
  try {
    asn1 = asn1js.fromBER(toArrayBuffer(der));
  } catch (err) {
    throw new ChainValidationError(`parse ${label}: ${(err as Error).message}`);
  }
  if (asn1.offset === -1) {
    throw new ChainValidationError(`parse ${label}: invalid DER`);
  }
  try {
    return new pkijs.Certificate({ schema: asn1.result });
  } catch (err) {
    throw new ChainValidationError(`parse ${label} as X.509: ${(err as Error).message}`);
  }
}

function sameCertificate(a: pkijs.Certificate, b: pkijs.Certificate): boolean {
  const aBytes = new Uint8Array(a.toSchema().toBER(false));
  const bBytes = new Uint8Array(b.toSchema().toBER(false));
  if (aBytes.length !== bBytes.length) return false;
  for (let i = 0; i < aBytes.length; i++) {
    if (aBytes[i] !== bBytes[i]) return false;
  }
  return true;
}

/** Uint8Array's buffer may be a larger, shared ArrayBuffer with an offset — copy out just this view's bytes. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

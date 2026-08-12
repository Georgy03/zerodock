// Builds test attestation documents entirely in TypeScript, using
// WebCrypto + pkijs — the JS equivalent of internal/attest/mock.go on the
// Go side, generating a fresh throwaway P-384 root+leaf cert chain and
// signing a real COSE_Sign1 document with it.
//
// This is what makes the whole verifier testable without a running
// enclave or even a running Go binary: build fixtures against the SAME
// wire shape MockAttester produces, verify the browser code against
// those, and — per week 2/3's discipline — it works against real NSM
// documents unchanged, because the wire format is identical either way.
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { encode } from "cborg";

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  pkijs.setEngine(
    "test-engine",
    new pkijs.CryptoEngine({ name: "test-engine", crypto, subtle: crypto.subtle }) as unknown as pkijs.ICryptoEngine,
  );
  engineReady = true;
}

async function generateP384KeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
}

async function buildCert(opts: {
  commonName: string;
  publicKey: CryptoKey;
  signWith: CryptoKey;
  issuerCommonName: string;
  isCA: boolean;
  notBefore?: Date;
  notAfter?: Date;
}): Promise<pkijs.Certificate> {
  ensureEngine();
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: Math.floor(Math.random() * 1_000_000) + 1 });

  cert.issuer.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: opts.issuerCommonName }) }),
  );
  cert.subject.typesAndValues.push(
    new pkijs.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: opts.commonName }) }),
  );

  cert.notBefore.value = opts.notBefore ?? new Date(Date.now() - 60 * 60 * 1000);
  cert.notAfter.value = opts.notAfter ?? new Date(Date.now() + 24 * 60 * 60 * 1000);

  if (opts.isCA) {
    const basicConstr = new pkijs.BasicConstraints({ cA: true });
    cert.extensions = [
      new pkijs.Extension({
        extnID: "2.5.29.19",
        critical: true,
        extnValue: basicConstr.toSchema().toBER(false),
        parsedValue: basicConstr,
      }),
    ];
  }

  await cert.subjectPublicKeyInfo.importKey(opts.publicKey);
  await cert.sign(opts.signWith, "SHA-384");
  return cert;
}

function certDER(cert: pkijs.Certificate): Uint8Array {
  return new Uint8Array(cert.toSchema(true).toBER(false));
}

export interface MockChain {
  rootDER: Uint8Array;
  leafDER: Uint8Array;
  leafPublicKey: CryptoKey;
  leafPrivateKey: CryptoKey;
}

/** Builds a fresh, throwaway root+leaf P-384 chain — the mock analogue of NewMockAttester on the Go side. */
export async function buildMockChain(overrides?: { notBefore?: Date; notAfter?: Date }): Promise<MockChain> {
  const rootKeys = await generateP384KeyPair();
  const rootCert = await buildCert({
    commonName: "ZeroDock Test Root (NOT FOR PRODUCTION)",
    issuerCommonName: "ZeroDock Test Root (NOT FOR PRODUCTION)",
    publicKey: rootKeys.publicKey,
    signWith: rootKeys.privateKey,
    isCA: true,
    // Root must cover the SAME validity window as the leaf below — a
    // test that widens the leaf's window (e.g. to test freshness against
    // an old checkDate) but leaves the root on its narrow default would
    // fail chain validation on ROOT expiry instead of exercising whatever
    // the test actually intends.
    notBefore: overrides?.notBefore,
    notAfter: overrides?.notAfter,
  });

  const leafKeys = await generateP384KeyPair();
  const leafCert = await buildCert({
    commonName: "ZeroDock Test Enclave (NOT FOR PRODUCTION)",
    issuerCommonName: "ZeroDock Test Root (NOT FOR PRODUCTION)",
    publicKey: leafKeys.publicKey,
    signWith: rootKeys.privateKey,
    isCA: false,
    notBefore: overrides?.notBefore,
    notAfter: overrides?.notAfter,
  });

  return {
    rootDER: certDER(rootCert),
    leafDER: certDER(leafCert),
    leafPublicKey: leafKeys.publicKey,
    leafPrivateKey: leafKeys.privateKey,
  };
}

export interface MockDocumentOptions {
  chain?: MockChain;
  userData: Uint8Array;
  nonce?: Uint8Array;
  timestamp?: number;
  pcrs?: Map<number, Uint8Array>;
  tagged?: boolean;
}

export interface MockDocument {
  bytes: Uint8Array;
  base64: string;
  chain: MockChain;
}

/**
 * Builds a complete, correctly-signed COSE_Sign1 attestation document —
 * exactly the shape internal/attest.MockAttester.Attest produces.
 * Individual fields can be overridden via `opts` so tests can build
 * adversarial variants (wrong root, tampered PCR, stale timestamp, etc.)
 * from a otherwise-valid baseline.
 */
export async function buildMockDocument(opts: MockDocumentOptions): Promise<MockDocument> {
  const chain = opts.chain ?? (await buildMockChain());

  const pcrs =
    opts.pcrs ??
    new Map<number, Uint8Array>([
      [0, randomBytes(48)],
      [1, randomBytes(48)],
      [2, randomBytes(48)],
    ]);

  const publicKeySPKI = new Uint8Array(await crypto.subtle.exportKey("spki", chain.leafPublicKey));

  const payload = new Map<string, unknown>([
    ["module_id", "zerodock-test-0000000000000000"],
    ["digest", "SHA384"],
    ["timestamp", opts.timestamp ?? Date.now()],
    ["pcrs", pcrs],
    ["certificate", chain.leafDER],
    ["cabundle", [chain.rootDER]],
    ["public_key", publicKeySPKI],
    ["user_data", opts.userData],
    ["nonce", opts.nonce ?? randomBytes(32)],
  ]);
  const payloadBytes = encode(payload);

  // Empty protected header — same as MockAttester (cose.Sign1 fills in
  // the alg header automatically); zero-length byte string.
  const protectedBytes = new Uint8Array(0);
  const externalAAD = new Uint8Array(0);
  const sigStructure = encode(["Signature1", protectedBytes, externalAAD, payloadBytes]);

  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-384" }, chain.leafPrivateKey, sigStructure),
  );

  const unprotected = new Map<number, number>([[1, -35]]); // alg: ES384 (COSE algorithm -35)
  const array = [protectedBytes, unprotected, payloadBytes, signature];
  const bytes = opts.tagged === false ? encode(array) : encodeTagged18(array);

  return { bytes, base64: bytesToBase64(bytes), chain };
}

/** CBOR-encodes `value` wrapped in tag 18 — the canonical COSE_Sign1 form. */
function encodeTagged18(array: unknown[]): Uint8Array {
  // cborg has no built-in "Tagged" convenience export needed here beyond
  // what encode() does for plain arrays — tag 18 (0xd2 for a
  // single-byte-argument tag) is prefixed by hand since we only ever need
  // this one fixed tag for these fixtures.
  const inner = encode(array);
  const out = new Uint8Array(inner.length + 1);
  out[0] = 0xd2; // major type 6 (tag), value 18
  out.set(inner, 1);
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

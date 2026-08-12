// The real, official AWS Nitro Enclaves root certificate — the same file
// as internal/verify/rootcerts/AWSNitroEnclavesRootG1.pem on the Go side
// (downloaded from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip,
// the address AWS's own attestation docs point to).
//
// THE SECURITY PROPERTY: this is an `?raw` import, which Vite inlines as
// a plain string INTO THE JS BUNDLE at build time. It is never fetched
// over the network at runtime. If this file were instead loaded via
// `fetch()`, anything that can intercept or tamper with that request
// (a compromised CDN, a malicious proxy, a supply-chain attack on
// whatever serves it) could swap in a different "trusted" root and this
// entire verifier would happily validate a forged attestation chain
// against it. Baking the root into the bundle means the trust anchor is
// fixed the moment this JavaScript is built and shipped — the same
// go:embed reasoning as internal/verify/rootcerts.go and
// internal/transport/rootcerts.go on the Go side, applied here for the
// same reason.
//
// The source file is named *.pem.txt, not *.pem: Vite's DEV SERVER
// refuses to serve files matching common secret-key extensions
// (`*.pem`, `*.crt`, etc. — server.fs.deny) as a default guard against
// accidentally leaking real secrets over the dev server. That protection
// doesn't apply here (this is a PUBLIC certificate, not a secret, and
// it's compiled into the bundle either way — this only affects
// `npm run dev`, never the production build), but there's no per-file
// exemption, so the extension is renamed instead of disabling the guard
// project-wide.
import rootCertPem from "../rootcerts/AWSNitroEnclavesRootG1.pem.txt?raw";

/** PEM text of the embedded AWS Nitro Enclaves root certificate. */
export const AWS_NITRO_ROOT_PEM = rootCertPem;

/**
 * Decodes the embedded root's PEM into raw DER bytes — the format
 * pkijs.Certificate.fromBER (see chain.ts) expects.
 */
export function awsNitroRootDER(): ArrayBuffer {
  return pemToDER(rootCertPem);
}

/** Strips PEM armor and base64-decodes to raw DER bytes. */
export function pemToDER(pem: string): ArrayBuffer {
  // Extract only the armored certificate body. The source file intentionally
  // contains a human-readable comment explaining its .pem.txt suffix; parsing
  // the bounded body keeps that documentation from becoming base64 input.
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!match) throw new Error("embedded AWS Nitro root is not a PEM certificate");
  const base64 = match[1].replace(/\s+/g, "");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

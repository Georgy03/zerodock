import { describe, expect, it } from "vitest";
import encodedRealNSMDocument from "../../../testdata/real-nsm-cose.b64?raw";
import { buildSigStructure, decodeCOSESign1 } from "./cose";
import { validateChain } from "./chain";
import { verifySignature } from "./signature";

describe("real NSM cross-implementation fixture", () => {
  it("accepts the exact same document as the Go verifier", async () => {
    // internal/attest/real_nsm_cross_test.go reads this same fixture and runs
    // it through verify.Verify. Sharing bytes across both test suites makes
    // any future Go/TypeScript divergence a permanent regression failure.
    const raw = Uint8Array.from(atob(encodedRealNSMDocument.trim()), (char) => char.charCodeAt(0));
    const document = decodeCOSESign1(raw);

    expect(document.signature).toHaveLength(96); // COSE ES384 is raw r||s.
    const sigStructure = Uint8Array.from(buildSigStructure(document));
    const sigStructureDigest = new Uint8Array(await crypto.subtle.digest("SHA-384", sigStructure));
    expect(bytesToHex(sigStructureDigest)).toBe(
      "a3cba2dde5aa681ec24c26dbc5eb98450c6ea0ba0126474b5e68f2f8a4e7adb74170ce534a2fe5957dd162ca72bf9674",
    );

    const chain = await validateChain(
      document.payload.certificate,
      document.payload.cabundle,
      new Date(document.payload.timestamp),
    );
    const leafSPKI = chain.leaf.subjectPublicKeyInfo.toSchema().toBER(false);
    await expect(verifySignature(document, leafSPKI)).resolves.toBeUndefined();

    expect(chain.leaf.subject.typesAndValues.length).toBeGreaterThan(0);
  });
});

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Adversarial scenarios include a truncated document, a wrong-root chain,
// post-signing PCR0 tampering, a validly signed but unpublished PCR0, and a stale
// timestamp — each asserted to render as FAILED, never verified. These
// exercise verifyShareResponse() as a whole (the same entry point
// App.tsx calls), not the individual check functions in isolation —
// what matters here is that the ORCHESTRATOR fails closed for each of
// these, not just that some inner function throws.
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildMockChain, buildMockDocument, randomBytes, bytesToBase64 } from "../test/fixtures";
import { verifyShareResponse } from "./verifier";
import { computeResultsHashHex, hexToBytes, bytesToHex } from "./hash";
import type { AttestedContent, ShareResponse } from "./types";

afterEach(() => {
  vi.unstubAllGlobals();
});

function sampleContent(): AttestedContent {
  return {
    scanner_version: "v1.2.3",
    account_id: "123456789012",
    scope_verified: true,
    time_verified: true,
    requested_regions: ["us-east-1"],
    scanned_regions: ["us-east-1"],
    checks: {
      "aws.ebs.encryption": {
        title: "Unencrypted EBS volumes",
        tier: "provider_attested",
        result: { status: "pass", findings: null, count: 0 },
      },
    },
  };
}

async function baselineDocAndResp(overrides?: {
  chain?: Awaited<ReturnType<typeof buildMockChain>>;
  timestamp?: number;
  pcrs?: Map<number, Uint8Array>;
}) {
  const content = sampleContent();
  const resultsHash = await computeResultsHashHex(content);
  const doc = await buildMockDocument({
    chain: overrides?.chain,
    userData: hexToBytes(resultsHash),
    timestamp: overrides?.timestamp,
    pcrs: overrides?.pcrs,
  });
  const pcrsHex: Record<string, string> = {};
  for (const [k, v] of overrides?.pcrs ??
    new Map<number, Uint8Array>([
      [0, randomBytes(48)],
      [1, randomBytes(48)],
      [2, randomBytes(48)],
    ])) {
    pcrsHex[String(k)] = bytesToHex(v);
  }
  const resp: ShareResponse = {
    ...content,
    scan_id: "adversarial-test",
    attested_at: new Date(overrides?.timestamp ?? Date.now()).toISOString(),
    received_at: new Date().toISOString(),
    results_sha384: resultsHash,
    attestation: {
      format: "COSE_Sign1/ES384 (mock attester)",
      mock: true,
      pcrs: pcrsHex,
      cose_sign1_base64: doc.base64,
    },
  };
  return { resp, doc };
}

describe("adversarial: truncated document", () => {
  it("renders failed, not verified, when the attestation bytes are cut short", async () => {
    const { resp, doc } = await baselineDocAndResp();
    const truncated = doc.bytes.slice(0, Math.floor(doc.bytes.length / 2));
    resp.attestation.cose_sign1_base64 = bytesToBase64(truncated);

    const result = await verifyShareResponse(resp, { freshnessWindowMs: 60_000 });

    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "decode")?.passed).toBe(false);
    // Nothing after decode should have even run.
    for (const name of ["chain", "signature", "freshness", "hash", "pcr0"] as const) {
      expect(result.checks.find((c) => c.name === name)?.passed).toBe(false);
    }
  });
});

describe("adversarial: wrong-root chain", () => {
  it("renders failed when the leaf chains to a root OTHER than the one the verifier trusts", async () => {
    const signingChain = await buildMockChain();
    const attackerChain = await buildMockChain(); // an unrelated root

    const { resp } = await baselineDocAndResp({ chain: signingChain });

    // Verify against attackerChain's root — a stand-in for "the real
    // embedded AWS Nitro root", which is exactly what happens in
    // production with no override at all: a mock-signed document's own
    // root is never the trusted one.
    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 60_000,
      testOnlyTrustedRootDER: attackerChain.rootDER,
    });

    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "decode")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "chain")?.passed).toBe(false);
  });

  it("renders failed against the REAL embedded AWS Nitro root with no override at all", async () => {
    const { resp } = await baselineDocAndResp();
    const result = await verifyShareResponse(resp, { freshnessWindowMs: 60_000 });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "chain")?.passed).toBe(false);
  });
});

describe("adversarial: mismatched PCR0", () => {
  it("renders failed when PCR0 is altered after the document was signed", async () => {
    const chain = await buildMockChain();
    const goodPcrs = new Map<number, Uint8Array>([
      [0, randomBytes(48)],
      [1, randomBytes(48)],
      [2, randomBytes(48)],
    ]);
    const { resp, doc } = await baselineDocAndResp({ chain, pcrs: goodPcrs });

    // Tamper with PCR0 directly in the already-signed CBOR bytes — the
    // realistic version of "PCR0 doesn't match what was signed" (as
    // opposed to a value the SENDER claims separately; PCR0 only exists
    // inside the signed payload, so a mismatch necessarily means the
    // signed bytes were altered after signing). We locate PCR0's 48
    // bytes in the raw document and flip one, which changes the payload
    // without updating the signature — exactly what an attacker
    // splicing in a fake PCR0 would produce.
    const original = goodPcrs.get(0)!;
    const idx = indexOfSubarray(doc.bytes, original);
    expect(idx).toBeGreaterThanOrEqual(0); // sanity: we actually found it

    const tampered = new Uint8Array(doc.bytes);
    tampered[idx] ^= 0xff;
    resp.attestation.cose_sign1_base64 = bytesToBase64(tampered);

    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 60_000,
      testOnlyTrustedRootDER: chain.rootDER,
    });

    expect(result.status).toBe("failed");
    // Decoding still succeeds (it's still well-formed CBOR) and chain
    // validation is unaffected (the leaf certificate wasn't touched) —
    // it's specifically the SIGNATURE that must fail, because the signed
    // payload no longer matches what the leaf key actually signed.
    expect(result.checks.find((c) => c.name === "decode")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "chain")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "signature")?.passed).toBe(false);
  });

  it("fails check 6 when a valid Nitro signature carries an unpublished PCR0", async () => {
    const chain = await buildMockChain();
    const signedPCR0 = new Uint8Array(48).fill(0xaa);
    const pcrs = new Map<number, Uint8Array>([
      [0, signedPCR0],
      [1, randomBytes(48)],
      [2, randomBytes(48)],
    ]);
    const { resp } = await baselineDocAndResp({ chain, pcrs });

    // The document and signature are untouched and therefore valid. Only the
    // independent release manifest disagrees, which must reach and fail the
    // scanner-identity check rather than signature verification.
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ PCR0: "bb".repeat(48) }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 60_000,
      testOnlyTrustedRootDER: chain.rootDER,
    });

    expect(result.status).toBe("failed");
    for (const name of ["decode", "chain", "signature", "freshness", "hash"] as const) {
      expect(result.checks.find((check) => check.name === name)?.passed).toBe(true);
    }
    expect(result.checks.find((check) => check.name === "pcr0")?.passed).toBe(false);
  });
});

describe("adversarial: substituted scanner release", () => {
  it("fails the attested hash before fetching a manifest from the substituted tag", async () => {
    const chain = await buildMockChain();
    const { resp } = await baselineDocAndResp({ chain });
    resp.scanner_version = "v9.9.9";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 60_000,
      testOnlyTrustedRootDER: chain.rootDER,
    });

    expect(result.status).toBe("failed");
    expect(result.checks.find((check) => check.name === "hash")?.passed).toBe(false);
    expect(result.checks.find((check) => check.name === "pcr0")?.detail).toContain("Not run");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("adversarial: stale timestamp", () => {
  it("renders failed when the attested timestamp is outside the freshness window", async () => {
    const chain = await buildMockChain({
      // Widen the test cert's own validity window so this failure is
      // specifically about the FRESHNESS check, not an incidental
      // certificate-expiry failure in chain validation.
      notBefore: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000),
      notAfter: new Date(Date.now() + 400 * 24 * 60 * 60 * 1000),
    });
    const staleTimestamp = Date.now() - 365 * 24 * 60 * 60 * 1000; // one year ago
    const { resp } = await baselineDocAndResp({ chain, timestamp: staleTimestamp });

    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 30 * 24 * 60 * 60 * 1000, // 30-day window
      testOnlyTrustedRootDER: chain.rootDER,
    });

    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "decode")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "chain")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "signature")?.passed).toBe(true);
    expect(result.checks.find((c) => c.name === "freshness")?.passed).toBe(false);
  });
});

function indexOfSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

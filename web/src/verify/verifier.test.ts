import { afterEach, describe, expect, it, vi } from "vitest";
import { buildMockChain, buildMockDocument } from "../test/fixtures";
import { verifyShareResponse } from "./verifier";
import { computeResultsHashHex, hexToBytes, bytesToHex } from "./hash";
import { decodeCOSESign1 } from "./cose";
import type { AttestedContent, ShareResponse } from "./types";

afterEach(() => {
  vi.unstubAllGlobals();
});

function sampleContent(): AttestedContent {
  return {
    scanner_version: "v1.2.3",
    organization_verified: true,
    no_organization: true,
    accounts_listed: ["123456789012"],
    accounts_scanned: ["123456789012"],
    account_id: "123456789012",
    scope_verified: true,
    time_verified: true,
    requested_regions: ["us-east-1"],
    scanned_regions: ["us-east-1"],
    checks: {
      "aws.ebs.encryption": {
        title: "Unencrypted EBS volumes",
        tier: "provider_attested",
        result: { status: "fail", findings: ["us-east-1: unencrypted EBS volume vol-abc123"], count: 2 },
      },
      "aws.iam.root_mfa": {
        title: "Root account without MFA enabled",
        tier: "provider_attested",
        result: { status: "pass", findings: null, count: 1 },
      },
    },
  };
}

interface BuildOptions {
  content?: AttestedContent;
  chain?: Awaited<ReturnType<typeof buildMockChain>>;
  timestamp?: number;
  pcrs?: Map<number, Uint8Array>;
  tagged?: boolean;
  /** Deliberately break the user_data / results hash relationship, for the mismatch test. */
  corruptUserData?: boolean;
}

/** Builds a fully self-consistent (ShareResponse, raw document bytes) pair from a mock-signed chain. */
export async function buildValidShareResponse(
  opts: BuildOptions = {},
): Promise<{ resp: ShareResponse; documentBytes: Uint8Array; chain: Awaited<ReturnType<typeof buildMockChain>> }> {
  const content = opts.content ?? sampleContent();
  const resultsHash = await computeResultsHashHex(content);
  const correctUserData = hexToBytes(resultsHash);
  // Flip one byte, so the resulting user_data provably does NOT match a
  // fresh hash of `content` — used by the hash-mismatch adversarial test.
  const userData = opts.corruptUserData ? xorFirstByte(correctUserData) : correctUserData;

  const doc = await buildMockDocument({
    chain: opts.chain,
    userData,
    timestamp: opts.timestamp,
    pcrs: opts.pcrs,
    tagged: opts.tagged,
  });

  const pcrsHex: Record<string, string> = {};
  for (const [k, v] of decodeCOSESign1(doc.bytes).payload.pcrs) pcrsHex[String(k)] = bytesToHex(v);

  const resp: ShareResponse = {
    ...content,
    scan_id: "test-scan-1",
    attested_at: new Date(opts.timestamp ?? Date.now()).toISOString(),
    received_at: new Date().toISOString(),
    results_sha384: resultsHash,
    attestation: {
      format: "COSE_Sign1/ES384 (mock attester)",
      mock: true,
      pcrs: pcrsHex,
      cose_sign1_base64: doc.base64,
    },
  };

  return { resp, documentBytes: doc.bytes, chain: doc.chain };
}

function xorFirstByte(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes);
  out[0] ^= 0xff;
  return out;
}

describe("fixture sanity", () => {
  it("decodes what buildMockDocument produced (tagged)", async () => {
    const { documentBytes } = await buildValidShareResponse();
    const doc = decodeCOSESign1(documentBytes);
    expect(doc.payload.module_id).toBe("zerodock-test-0000000000000000");
    expect(doc.payload.pcrs.size).toBe(3);
  });

  it("decodes what buildMockDocument produced (untagged)", async () => {
    const { documentBytes } = await buildValidShareResponse({ tagged: false });
    const doc = decodeCOSESign1(documentBytes);
    expect(doc.payload.module_id).toBe("zerodock-test-0000000000000000");
  });
});

describe("verifyShareResponse — happy path (against an injected test root)", () => {
  it("verifies end to end when the chain is validated against the matching test root", async () => {
    const { resp, chain } = await buildValidShareResponse();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ PCR0: resp.attestation.pcrs["0"] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await verifyShareResponse(resp, {
      freshnessWindowMs: 60_000,
      testOnlyTrustedRootDER: chain.rootDER,
    });
    expect(result.status).toBe("verified");
    expect(result.checks).toHaveLength(6);
    expect(result.checks.every((c) => c.passed)).toBe(true);
    expect(result.checks.at(-1)?.name).toBe("pcr0");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://raw.githubusercontent.com/Georgy03/zerodock/v1.2.3/pcrs.json",
      expect.any(Object),
    );
  });

  it("fails chain validation against the real embedded AWS Nitro root (no override) — proves there is no mock escape hatch", async () => {
    const { resp } = await buildValidShareResponse();
    const result = await verifyShareResponse(resp, { freshnessWindowMs: 60_000 });
    expect(result.status).toBe("failed");
    expect(result.checks.find((c) => c.name === "chain")?.passed).toBe(false);
    expect(result.checks.find((c) => c.name === "decode")?.passed).toBe(true);
  });
});

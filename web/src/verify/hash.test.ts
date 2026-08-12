// Dedicated tests for the canonical-JSON / hash-recompute logic — see
// hash.ts's header comment for why this file exists: replicating Go's
// encoding/json.Marshal byte-for-byte is fiddly, and a mistake here would
// fail every real, legitimate report rather than throwing an obvious
// error.
import { describe, expect, it } from "vitest";
import { checkResultsHash, computeResultsHashHex, hexToBytes, bytesToHex, HashMismatchError } from "./hash";
import type { AttestedContent, ShareResponse } from "./types";

function baseContent(): AttestedContent {
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
    checks: {},
  };
}

describe("computeResultsHashHex — field order and omitempty", () => {
  it("matches a hand-computed Go-shaped JSON string for a minimal record", async () => {
    const content = baseContent();
    // What Go's encoding/json.Marshal would produce for this exact
    // struct: declaration order, omitempty fields dropped entirely.
    const expectedJSON =
      '{"scanner_version":"v1.2.3","organization_verified":true,"no_organization":true,"accounts_listed":["123456789012"],"accounts_scanned":["123456789012"],"account_id":"123456789012","scope_verified":true,"time_verified":true,"requested_regions":["us-east-1"],"scanned_regions":["us-east-1"],"checks":{}}';
    const expectedDigest = await crypto.subtle.digest("SHA-384", new TextEncoder().encode(expectedJSON));
    const expectedHex = bytesToHex(new Uint8Array(expectedDigest));

    expect(await computeResultsHashHex(content)).toBe(expectedHex);
  });

  it("omits scope_warning/time_warning/regions_warning entirely when empty", async () => {
    const withEmpty = { ...baseContent(), scope_warning: "", time_warning: "", regions_warning: "" };
    const withoutFields = baseContent();
    expect(await computeResultsHashHex(withEmpty)).toBe(await computeResultsHashHex(withoutFields));
  });

  it("includes warning fields, in declaration order, when non-empty", async () => {
    const content: AttestedContent = {
      ...baseContent(),
      scope_verified: false,
      scope_warning: "could not confirm account",
    };
    const expectedJSON =
      '{"scanner_version":"v1.2.3","organization_verified":true,"no_organization":true,"accounts_listed":["123456789012"],"accounts_scanned":["123456789012"],"account_id":"123456789012","scope_verified":false,"scope_warning":"could not confirm account","time_verified":true,"requested_regions":["us-east-1"],"scanned_regions":["us-east-1"],"checks":{}}';
    const expectedDigest = await crypto.subtle.digest("SHA-384", new TextEncoder().encode(expectedJSON));
    expect(await computeResultsHashHex(content)).toBe(bytesToHex(new Uint8Array(expectedDigest)));
  });

  it("sorts check IDs alphabetically, matching Go's map key sort", async () => {
    const inOrderA: AttestedContent = {
      ...baseContent(),
      checks: {
        "z.check": { title: "Z", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
        "a.check": { title: "A", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
      },
    };
    const inOrderB: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": { title: "A", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
        "z.check": { title: "Z", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
      },
    };
    // Insertion order differs, but the hash must not — both must sort to
    // the same canonical form.
    expect(await computeResultsHashHex(inOrderA)).toBe(await computeResultsHashHex(inOrderB));
  });

  it("sorts per-account result keys and includes them after the aggregate result", async () => {
    const accountResult = { status: "pass" as const, findings: null, count: 1 };
    const first: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": {
          title: "A",
          tier: "provider_attested",
          result: { status: "pass", findings: null, count: 2 },
          accounts: { "222222222222": accountResult, "111111111111": accountResult },
        },
      },
    };
    const second: AttestedContent = {
      ...first,
      checks: {
        "a.check": {
          ...first.checks["a.check"],
          accounts: { "111111111111": accountResult, "222222222222": accountResult },
        },
      },
    };

    expect(await computeResultsHashHex(first)).toBe(await computeResultsHashHex(second));
  });

  it("preserves null findings as JSON null, not an empty array", async () => {
    const withNull: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": { title: "A", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
      },
    };
    const withEmptyArray: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": { title: "A", tier: "provider_attested", result: { status: "pass", findings: [], count: 0 } },
      },
    };
    expect(await computeResultsHashHex(withNull)).not.toBe(await computeResultsHashHex(withEmptyArray));
  });

  it("HTML-escapes <, >, & the same way Go's Marshal does", async () => {
    const content: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": {
          title: "A",
          tier: "provider_attested",
          result: { status: "fail", findings: ["security group allows <all> traffic & more"], count: 1 },
        },
      },
    };
    const expectedJSON =
      '{"scanner_version":"v1.2.3","organization_verified":true,"no_organization":true,"accounts_listed":["123456789012"],"accounts_scanned":["123456789012"],"account_id":"123456789012","scope_verified":true,"time_verified":true,"requested_regions":["us-east-1"],"scanned_regions":["us-east-1"],"checks":{"a.check":{"title":"A","tier":"provider_attested","result":{"status":"fail","findings":["security group allows \\u003call\\u003e traffic \\u0026 more"],"count":1}}}}';
    const expectedDigest = await crypto.subtle.digest("SHA-384", new TextEncoder().encode(expectedJSON));
    expect(await computeResultsHashHex(content)).toBe(bytesToHex(new Uint8Array(expectedDigest)));
  });

  it("includes Result.region only when non-empty", async () => {
    const withRegion: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": {
          title: "A",
          tier: "provider_attested",
          result: { status: "pass", findings: null, count: 0, region: "us-east-1" },
        },
      },
    };
    const withoutRegion: AttestedContent = {
      ...baseContent(),
      checks: {
        "a.check": { title: "A", tier: "provider_attested", result: { status: "pass", findings: null, count: 0 } },
      },
    };
    expect(await computeResultsHashHex(withRegion)).not.toBe(await computeResultsHashHex(withoutRegion));
  });
});

describe("checkResultsHash", () => {
  function shareResponseFor(content: AttestedContent, resultsHash: string): ShareResponse {
    return {
      ...content,
      scan_id: "x",
      attested_at: new Date().toISOString(),
      received_at: new Date().toISOString(),
      results_sha384: resultsHash,
      attestation: { format: "test", mock: true, pcrs: {}, cose_sign1_base64: "" },
    };
  }

  it("succeeds when user_data and results_sha384 both match a fresh hash", async () => {
    const content = baseContent();
    const hex = await computeResultsHashHex(content);
    const resp = shareResponseFor(content, hex);
    await expect(checkResultsHash(resp, hexToBytes(hex))).resolves.toMatchObject({ computedHex: hex });
  });

  it("throws when user_data doesn't match a fresh hash of the content", async () => {
    const content = baseContent();
    const hex = await computeResultsHashHex(content);
    const resp = shareResponseFor(content, hex);
    const wrongUserData = hexToBytes(hex);
    wrongUserData[0] ^= 0xff;
    await expect(checkResultsHash(resp, wrongUserData)).rejects.toBeInstanceOf(HashMismatchError);
  });

  it("throws when results_sha384 itself doesn't match the content (internally inconsistent response)", async () => {
    const content = baseContent();
    const hex = await computeResultsHashHex(content);
    const wrongHex = "0".repeat(96);
    const resp = shareResponseFor(content, wrongHex);
    // user_data matches the REAL hash, but results_sha384 field claims something else.
    await expect(checkResultsHash(resp, hexToBytes(hex))).rejects.toBeInstanceOf(HashMismatchError);
  });

  it("throws when user_data is empty", async () => {
    const content = baseContent();
    const hex = await computeResultsHashHex(content);
    const resp = shareResponseFor(content, hex);
    await expect(checkResultsHash(resp, new Uint8Array(0))).rejects.toBeInstanceOf(HashMismatchError);
  });
});

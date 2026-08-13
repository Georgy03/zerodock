// Check #6 answers a different question from certificate/signature
// verification. A valid AWS Nitro signature proves that *an* enclave produced
// the document; matching PCR0 against ZeroDock's independently published
// release measurement proves that enclave ran the expected scanner image.
//
// The manifest deliberately lives on raw.githubusercontent.com rather than the
// ZeroDock API. If the API served both the report and its expected PCR0, a
// compromised API could swap both together and make modified enclave code look
// legitimate. scanner_version is covered by the attested results hash, so the
// API cannot select a different tag after the enclave signs. The separate
// GitHub origin makes substitution require compromising the published
// source/release record too.

const RELEASE_MANIFEST_BASE = "https://raw.githubusercontent.com/Georgy03/zerodock";
const RELEASE_TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;

const SHA384_HEX = /^[0-9a-f]{96}$/;

// Release tags are immutable policy, but v0.3.0 was tagged after an earlier
// measurement had already produced a real report. These are immutable Git
// commit URLs, not mutable branches: they preserve the historically published
// pcrs.json rather than rewriting the tag and breaking CDN caches or audit
// links. The unversioned entry predates scanner_version being attested.
const HISTORICAL_MANIFESTS: Record<string, readonly string[]> = {
  "v0.3.0": ["https://raw.githubusercontent.com/Georgy03/zerodock/0cf53a6741fb26cf7b13b9a2ab6e329dc615aee7/pcrs.json"],
};
const PRE_VERSION_MANIFESTS = [
  "https://raw.githubusercontent.com/Georgy03/zerodock/77cdfcc3a962f06e7d638c50e403f01f645d452d/pcrs.json",
] as const;

export class PCRVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PCRVerificationError";
  }
}

interface PublishedPCRs {
  PCR0: string;
  PCR1?: string;
  PCR2?: string;
}

export interface PCRCheckResult {
  actualPCR0: string;
  publishedPCR0: string;
  sourceURL: string;
}

/**
 * Fetches the release measurements from GitHub and compares the attestation's
 * signed PCR0 against the published value. Network, HTTP, JSON-shape, and
 * mismatch failures all throw: an unavailable release manifest must never be
 * interpreted as a successful identity check.
 */
export async function checkPublishedPCR0(
  attestedPCR0: Uint8Array | undefined,
  scannerVersion: string | undefined,
  fetchFn: typeof fetch = fetch,
): Promise<PCRCheckResult> {
  if (!attestedPCR0 || attestedPCR0.length !== 48) {
    throw new PCRVerificationError("Attestation is missing a 48-byte SHA-384 PCR0 measurement.");
  }

  const actualPCR0 = bytesToHex(attestedPCR0);
  if (scannerVersion === undefined) {
    return matchHistoricalManifest(actualPCR0, PRE_VERSION_MANIFESTS, fetchFn, "This legacy attestation has no scanner_version");
  }

  const sourceURL = publishedPCRsURL(scannerVersion);
  const publishedPCR0 = await fetchManifestPCR0(sourceURL, fetchFn);
  if (actualPCR0 === publishedPCR0) return { actualPCR0, publishedPCR0, sourceURL };

  const historical = HISTORICAL_MANIFESTS[scannerVersion] ?? [];
  if (historical.length > 0) {
    try {
      return await matchHistoricalManifest(actualPCR0, historical, fetchFn, `No historical ${scannerVersion} measurement matched`);
    } catch (err) {
      if (!(err instanceof PCRVerificationError)) throw err;
      // Keep the canonical tag mismatch in the final error. It is the most
      // actionable explanation for a scanner version not listed above.
    }
  }
  throw new PCRVerificationError(`Attested PCR0 ${actualPCR0} does not match published ZeroDock PCR0 ${publishedPCR0}.`);
}

async function matchHistoricalManifest(actualPCR0: string, urls: readonly string[], fetchFn: typeof fetch, prefix: string): Promise<PCRCheckResult> {
  for (const sourceURL of urls) {
    const publishedPCR0 = await fetchManifestPCR0(sourceURL, fetchFn);
    if (actualPCR0 === publishedPCR0) return { actualPCR0, publishedPCR0, sourceURL };
  }
  throw new PCRVerificationError(`${prefix}; its signed PCR0 does not match any immutable historical release manifest.`);
}

async function fetchManifestPCR0(sourceURL: string, fetchFn: typeof fetch): Promise<string> {
  let response: Response;
  try {
    response = await fetchFn(sourceURL, { headers: { Accept: "application/json" }, cache: "no-cache" });
  } catch (err) {
    throw new PCRVerificationError(`Could not fetch published PCR measurements from GitHub: ${errorMessage(err)}`);
  }
  if (!response.ok) throw new PCRVerificationError(`GitHub returned HTTP ${response.status} fetching published PCR measurements.`);
  try {
    return parsePublishedPCR0(await response.json());
  } catch (err) {
    if (err instanceof PCRVerificationError) throw err;
    throw new PCRVerificationError(`Published PCR manifest is not valid JSON: ${errorMessage(err)}`);
  }
}

/**
 * Builds a URL only within ZeroDock's fixed GitHub repository. The version is
 * signed indirectly through user_data, and this strict tag grammar prevents a
 * malicious value from escaping the single path segment or selecting `main`.
 */
export function publishedPCRsURL(scannerVersion: string | undefined): string {
  if (!scannerVersion) {
    throw new PCRVerificationError("Attested content does not include scanner_version.");
  }
  if (!RELEASE_TAG.test(scannerVersion)) {
    throw new PCRVerificationError(
      `Attested scanner_version ${JSON.stringify(scannerVersion)} is not an immutable release tag such as v1.2.3.`,
    );
  }
  return `${RELEASE_MANIFEST_BASE}/${scannerVersion}/pcrs.json`;
}

function parsePublishedPCR0(value: unknown): string {
  if (!isRecord(value) || typeof value.PCR0 !== "string") {
    throw new PCRVerificationError('Published PCR manifest must contain a string field named "PCR0".');
  }

  const normalized = value.PCR0.toLowerCase();
  if (!SHA384_HEX.test(normalized)) {
    throw new PCRVerificationError("Published PCR0 must be exactly 96 hexadecimal characters (SHA-384).");
  }
  return normalized;
}

function isRecord(value: unknown): value is PublishedPCRs & Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Recomputes SHA-384 over the fetched AttestedContent and confirms it
// matches the attestation document's own sealed user_data — the browser
// mirror of internal/api's server-side re-hash check, and ultimately of
// what cmd/scanner computed in the first place (see internal/report's
// package comment: this is the "one shared shape, both sides marshal it
// identically" invariant, now extended a THIRD time to this TypeScript
// port).
//
// THE HARD PART: Go's encoding/json.Marshal has specific, non-obvious
// serialization rules that plain JSON.stringify does NOT replicate:
//   1. Struct fields are emitted in DECLARATION ORDER (not alphabetical) —
//      handled here by building each object with keys inserted in that
//      exact order; JS objects preserve string-key insertion order.
//   2. `omitempty` fields (scope_warning, time_warning, regions_warning,
//      Result.region) are OMITTED ENTIRELY when empty, not emitted as ""
//      or null.
//   3. map[string]CheckOutput keys are sorted (Go's json package sorts
//      map keys before emitting them) — handled by sorting check IDs here
//      before building the checks object.
//   4. A nil []string (Go: no findings recorded) marshals as JSON `null`,
//      not `[]` — preserved here by passing `findings` through as-is
//      rather than defaulting it to an array.
//   5. Go's Marshal, by default, HTML-escapes '<', '>', '&', U+2028, and
//      U+2029 as \u00XX / \uXXXX inside strings. JSON.stringify does NOT.
//      A finding string mentioning e.g. "<script>" or a security group
//      description containing '&' would otherwise silently produce
//      different bytes on the two sides. goJSONString below replicates
//      Go's exact escaping.
// Get any ONE of these wrong for real submitted data and this check
// fails on a perfectly legitimate report — so this file, not the crypto,
// is where a subtle bug is most likely to hide. It's covered accordingly
// in hash.test.ts.
import type { AttestedContent, CheckResult, ShareResponse } from "./types";

export class HashMismatchError extends Error {}

export interface HashCheckResult {
  computedHex: string;
  userDataHex: string;
  resultsShaFieldHex: string;
}

/**
 * Recomputes SHA-384 over resp's AttestedContent fields and confirms the
 * result matches BOTH userData (the attestation document's own sealed
 * user_data — the check that actually matters cryptographically) and
 * resp.results_sha384 (the API's own claimed hash — a cheap extra
 * cross-check that the server didn't hand us a results_sha384 string
 * that doesn't even match the content it's sitting next to).
 */
export async function checkResultsHash(resp: ShareResponse, userData: Uint8Array | null): Promise<HashCheckResult> {
  if (!userData || userData.length === 0) {
    throw new HashMismatchError("attestation document has no user_data to compare against");
  }

  const computedHex = await computeResultsHashHex(resp);
  const userDataHex = bytesToHex(userData);

  if (computedHex !== userDataHex) {
    throw new HashMismatchError(
      `recomputed SHA-384 (${computedHex.slice(0, 16)}...) does not match the attestation's user_data (${userDataHex.slice(0, 16)}...)`,
    );
  }
  if (resp.results_sha384.toLowerCase() !== computedHex) {
    throw new HashMismatchError(
      `recomputed SHA-384 does not match the API's own claimed results_sha384 field — the response is internally inconsistent`,
    );
  }

  return { computedHex, userDataHex, resultsShaFieldHex: resp.results_sha384.toLowerCase() };
}

/**
 * Computes the canonical SHA-384 hex digest of content's AttestedContent
 * fields — the single source of truth both checkResultsHash (production)
 * and the test fixtures (src/test/fixtures.ts) use, so a fixture can
 * never silently drift from what the real check actually computes.
 */
export async function computeResultsHashHex(content: AttestedContent): Promise<string> {
  const canonical = goJSONMarshal(buildAttestedContentForHashing(content));
  const digest = await crypto.subtle.digest("SHA-384", new TextEncoder().encode(canonical));
  return bytesToHex(new Uint8Array(digest));
}

/** Builds the field-ordered, omitempty-aware object matching internal/report.AttestedContent's JSON shape. */
function buildAttestedContentForHashing(resp: AttestedContent): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  // Go uses omitempty so legacy reports, issued before scanner_version was
  // added, retain their original byte-for-byte hash representation.
  if (resp.scanner_version) obj.scanner_version = resp.scanner_version;
  if (resp.organization_verified) obj.organization_verified = resp.organization_verified;
  if (resp.org_id) obj.org_id = resp.org_id;
  if (resp.no_organization) obj.no_organization = resp.no_organization;
  if (resp.organization_warning) obj.organization_warning = resp.organization_warning;
  if (resp.accounts_listed && resp.accounts_listed.length > 0) obj.accounts_listed = resp.accounts_listed;
  if (resp.accounts_scanned && resp.accounts_scanned.length > 0) obj.accounts_scanned = resp.accounts_scanned;
  if (resp.supabase_organization_id) obj.supabase_organization_id = resp.supabase_organization_id;
  if (resp.projects_listed && resp.projects_listed.length > 0) obj.projects_listed = resp.projects_listed;
  if (resp.projects_scanned && resp.projects_scanned.length > 0) obj.projects_scanned = resp.projects_scanned;
  if (resp.gcp_organization_id) obj.gcp_organization_id = resp.gcp_organization_id;
  if (resp.gcp_projects_listed && resp.gcp_projects_listed.length > 0) obj.gcp_projects_listed = resp.gcp_projects_listed;
  if (resp.gcp_projects_scanned && resp.gcp_projects_scanned.length > 0) obj.gcp_projects_scanned = resp.gcp_projects_scanned;
  obj.account_id = resp.account_id;
  obj.scope_verified = resp.scope_verified;
  if (resp.scope_warning) obj.scope_warning = resp.scope_warning;
  obj.time_verified = resp.time_verified;
  if (resp.time_warning) obj.time_warning = resp.time_warning;
  obj.requested_regions = resp.requested_regions;
  obj.scanned_regions = resp.scanned_regions;
  if (resp.regions_warning) obj.regions_warning = resp.regions_warning;

  const checksObj: Record<string, unknown> = {};
  // Go's encoding/json sorts map[string]V keys before emitting them
  // (ordinary string comparison — byte-wise for the ASCII check IDs this
  // codebase actually uses, which is also exactly what JS's default
  // .sort() does for ASCII strings).
  for (const id of Object.keys(resp.checks).sort()) {
    const check = resp.checks[id];
    const checkObj: Record<string, unknown> = {
      title: check.title,
      tier: check.tier,
      result: buildResultForHashing(check.result),
    };
    if (check.accounts && Object.keys(check.accounts).length > 0) {
      const accountResults: Record<string, unknown> = {};
      for (const accountID of Object.keys(check.accounts).sort()) {
        accountResults[accountID] = buildResultForHashing(check.accounts[accountID]);
      }
      checkObj.accounts = accountResults;
    }
    checksObj[id] = checkObj;
  }
  obj.checks = checksObj;

  return obj;
}

function buildResultForHashing(result: CheckResult): Record<string, unknown> {
  const obj: Record<string, unknown> = {
    status: result.status,
    // Passed through AS-IS: `null` must stay `null` (Go's nil slice),
    // not become `[]` — see point 4 in this file's header comment.
    findings: result.findings,
    count: result.count,
  };
  if (result.region) obj.region = result.region;
  // Evidence was appended to checks.Result with omitempty. Preserve the Go
  // field order and omit it for legacy reports so their hashes remain valid.
  if (result.evidence && result.evidence.length > 0) obj.evidence = result.evidence;
  return obj;
}

/** A minimal JSON serializer replicating Go's encoding/json.Marshal output exactly — see this file's header comment. */
function goJSONMarshal(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";
  if (typeof value === "string") return goJSONString(value);
  if (Array.isArray(value)) return `[${value.map(goJSONMarshal).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return `{${entries.map(([k, v]) => `${goJSONString(k)}:${goJSONMarshal(v)}`).join(",")}}`;
  }
  throw new Error(`goJSONMarshal: unsupported type ${typeof value}`);
}

const SHORT_ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

/** Replicates Go's exact string-escaping rules for encoding/json.Marshal — see this file's header comment, point 5. */
function goJSONString(s: string): string {
  let out = '"';
  for (const ch of s) {
    if (SHORT_ESCAPES[ch]) {
      out += SHORT_ESCAPES[ch];
      continue;
    }
    const code = ch.codePointAt(0)!;
    const needsUnicodeEscape =
      code < 0x20 || // control characters
      ch === "<" ||
      ch === ">" ||
      ch === "&" ||
      code === 0x2028 ||
      code === 0x2029;
    if (needsUnicodeEscape) {
      out += `\\u${code.toString(16).padStart(4, "0")}`;
    } else {
      out += ch;
    }
  }
  return out + '"';
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hexToBytes: odd-length hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

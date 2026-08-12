// This file mirrors, field-for-field, the Go types the backend actually
// sends: internal/report.{Report, AttestedContent, CheckOutput} (what
// GET /v1/share/{token} returns — see internal/api/view.go's
// verdictView) and internal/checks.{Tier, Result}.
//
// Keeping these as a hand-written mirror instead of trying to generate
// them means a change on the Go side is a compile error here, not a
// silent runtime mismatch — TypeScript won't let this file drift from
// what recomputeUserData (hash.ts) assumes the shape is.

/** Mirrors internal/checks.Tier. */
export type Tier = "provider_attested" | "actively_probed" | "infra_only";

/** Mirrors internal/checks.Result. */
export interface CheckResult {
  status: "pass" | "fail" | "error" | "not_in_use";
  findings: string[] | null;
  count: number;
  region?: string;
  evidence?: string[];
}

/** Mirrors internal/report.CheckOutput. */
export interface CheckOutput {
  title: string;
  tier: Tier;
  result: CheckResult;
  /** Signed per-account evidence; absent only on reports issued before org enumeration. */
  accounts?: Record<string, CheckResult>;
}

/**
 * Mirrors internal/report.AttestedContent — EXACTLY the bytes that were
 * hashed and sealed as the attestation's user_data on the Go side (see
 * that struct's big comment for why field order/omission behavior is a
 * wire format, not just a TypeScript convenience). hash.ts's
 * recomputeUserData depends on this shape matching precisely.
 */
export interface AttestedContent {
  /** Added after the first reports; omitted only when verifying legacy evidence. */
  scanner_version?: string;
  organization_verified?: boolean;
  org_id?: string;
  no_organization?: boolean;
  organization_warning?: string;
  accounts_listed?: string[];
  accounts_scanned?: string[];
  account_id: string;
  scope_verified: boolean;
  scope_warning?: string;
  time_verified: boolean;
  time_warning?: string;
  requested_regions: string[];
  scanned_regions: string[];
  regions_warning?: string;
  checks: Record<string, CheckOutput>;
}

/** The `attestation` object inside a GET /v1/share/{token} response. */
export interface AttestationView {
  format: string;
  mock: boolean;
  pcrs: Record<string, string>; // "0" | "1" | "2" -> hex
  cose_sign1_base64: string;
}

/**
 * The full JSON body GET /v1/share/{token} returns — see
 * internal/api/view.go's verdictView. AttestedContent's fields are
 * flattened onto this (matching how the Go side embeds AttestedContent
 * anonymously in its Report/verdictView types).
 */
export interface ShareResponse extends AttestedContent {
  scan_id: string;
  account_id: string;
  attested_at: string; // RFC3339
  received_at: string; // RFC3339
  results_sha384: string;
  attestation: AttestationView;
}

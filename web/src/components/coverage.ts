import type { AttestedContent } from "../verify/types";

export interface CoverageSummary {
  known: boolean;
  scanned: number;
  listed: number;
  note: string;
}

/** Builds the buyer-facing organization coverage claim from signed fields. */
export function summarizeCoverage(
  content: Pick<
    AttestedContent,
    "organization_verified" | "org_id" | "no_organization" | "organization_warning" | "accounts_listed" | "accounts_scanned"
  >,
): CoverageSummary {
  const listed = content.accounts_listed ?? [];
  const scanned = content.accounts_scanned ?? [];
  const known = content.organization_verified === true && listed.length > 0;

  if (!known) {
    return {
      known,
      scanned: scanned.length,
      listed: listed.length,
      note: content.organization_warning ?? "This legacy report did not attest organization enumeration.",
    };
  }
  if (content.no_organization) {
    return {
      known,
      scanned: scanned.length,
      listed: listed.length,
      note: "AWS explicitly reported that this account is not in an Organization; single-account fallback verified.",
    };
  }

  const missing = listed.length - scanned.length;
  return {
    known,
    scanned: scanned.length,
    listed: listed.length,
    note:
      missing > 0
        ? `${missing} listed account${missing === 1 ? " was" : "s were"} not scanned. ${content.organization_warning ?? "See per-account errors below."}`
        : `Complete AWS Organization coverage verified${content.org_id ? ` for ${content.org_id}` : ""}.`,
  };
}

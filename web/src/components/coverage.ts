import type { AttestedContent } from "../verify/types";

export interface CoverageSummary {
  known: boolean;
  scanned: number;
  listed: number;
  note: string;
}

/** GCP is a separate provider scope. Never sum it with AWS accounts: a
 * 18/18 AWS scan and 4/4 GCP scan are two independent coverage claims. */
export function summarizeGCPCoverage(
  content: Pick<AttestedContent, "gcp_organization_id" | "gcp_projects_listed" | "gcp_projects_scanned">,
): CoverageSummary | null {
  const listed = content.gcp_projects_listed ?? [];
  const scanned = content.gcp_projects_scanned ?? [];
  if (!content.gcp_organization_id && listed.length === 0 && scanned.length === 0) return null;
  const known = content.gcp_organization_id !== undefined && content.gcp_organization_id !== "" && listed.length > 0;
  const missing = listed.length - scanned.length;
  return {
    known,
    listed: listed.length,
    scanned: scanned.length,
    note: known
      ? missing > 0
        ? `${missing} listed GCP project${missing === 1 ? " was" : "s were"} not scanned.`
        : `Complete GCP Organization coverage verified for ${content.gcp_organization_id}.`
      : "GCP organization coverage is unavailable.",
  };
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

// Account-inventory drift detection, mirroring internal/scope.Detect on
// the Go side field-for-field (see that package's doc comment for the
// full reasoning). This file exists so ZeroDock's scope-drift claims
// never have to be trusted: ScopeEvents.tsx calls this over TWO
// INDEPENDENTLY VERIFIED attested verdicts (each one already ran through
// verifyShareResponse's chain/signature/hash checks), not over a
// server-asserted diff. If ZeroDock's own API were compromised and tried
// to hide a new, unreachable account by omitting a scope event from its
// response, this function would still catch it — because it never reads
// anything the API "says happened"; it only reads the two signed account
// inventories and recomputes the difference itself.
export interface AccountsSnapshot {
  listed: string[];
  scanned: string[];
}

export type ScopeEventKind = "account_added" | "account_removed" | "coverage_decreased";

export interface ScopeEvent {
  kind: ScopeEventKind;
  /** Set for account_added and account_removed. */
  accountId?: string;
  /** Set for account_added: was the new account also in the current scan's Scanned set? */
  scannerRolePresent?: boolean;
  /** Set for coverage_decreased. */
  previousScanned?: number;
  previousListed?: number;
  currentScanned?: number;
  currentListed?: number;
}

/**
 * Compares previous and current AccountsSnapshot and returns every
 * scope-drift event this transition represents. previous being null (no
 * prior verified scan to compare against) always returns []: there is
 * nothing to have drifted from yet.
 *
 * CoverageDecreased is checked by RATIO, not raw counts, on purpose:
 * 18/18 becoming 18/19 is coverage dropping, even though the "accounts
 * scanned" count didn't change — a 19th account appeared in AWS
 * Organizations with no scanner role deployed to it yet. That's the
 * differentiator case this whole feature exists to catch.
 */
export function detectScopeEvents(previous: AccountsSnapshot | null, current: AccountsSnapshot): ScopeEvent[] {
  if (!previous || (previous.listed.length === 0 && previous.scanned.length === 0)) {
    return [];
  }

  const events: ScopeEvent[] = [];
  const prevListed = new Set(previous.listed);
  const currListed = new Set(current.listed);
  const currScanned = new Set(current.scanned);

  for (const id of current.listed) {
    if (!prevListed.has(id)) {
      events.push({ kind: "account_added", accountId: id, scannerRolePresent: currScanned.has(id) });
    }
  }
  for (const id of previous.listed) {
    if (!currListed.has(id)) {
      events.push({ kind: "account_removed", accountId: id });
    }
  }

  if (previous.listed.length > 0 && current.listed.length > 0) {
    const prevRatio = previous.scanned.length / previous.listed.length;
    const currRatio = current.scanned.length / current.listed.length;
    if (currRatio < prevRatio) {
      events.push({
        kind: "coverage_decreased",
        previousScanned: previous.scanned.length,
        previousListed: previous.listed.length,
        currentScanned: current.scanned.length,
        currentListed: current.listed.length,
      });
    }
  }

  return events;
}

/** coverageRatio as a display string, e.g. "18 / 19". */
export function formatCoverageRatio(snapshot: AccountsSnapshot): string {
  return `${snapshot.scanned.length} / ${snapshot.listed.length}`;
}

/**
 * A coverage ratio only has its usual meaning when the scan was able to
 * independently enumerate an AWS Organization. Older reports predate that
 * capability, so their empty 0 / 0 inventory must never be presented as
 * "zero coverage" or used as a baseline for a coverage-drop warning.
 */
export function isOrganizationAwareSnapshot(
  snapshot: AccountsSnapshot,
  organizationVerified?: boolean,
  noOrganization?: boolean,
): boolean {
  return organizationVerified === true && !noOrganization && snapshot.listed.length > 0;
}

/** A buyer-facing label that distinguishes unavailable organization scope from 0 / 0 coverage. */
export function formatTimelineCoverage(
  snapshot: AccountsSnapshot,
  organizationVerified?: boolean,
  noOrganization?: boolean,
): string {
  if (!isOrganizationAwareSnapshot(snapshot, organizationVerified, noOrganization)) {
    return "No organization configured";
  }
  return formatCoverageRatio(snapshot);
}

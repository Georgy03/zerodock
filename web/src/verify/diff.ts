// This mirrors internal/diff/diff.go field-for-field. It only accepts report
// shapes whose attested content has already been independently verified by
// verifier.ts; the API's history response is transport, never the source of
// truth for a displayed change.
import type { AttestedContent, CheckOutput, CheckResult } from "./types";

export type DiffEventKind = "status_changed" | "new_finding" | "resolved_finding";
export type DiffSeverity = "regression" | "neutral" | "improvement";

export interface DiffEvent {
  kind: DiffEventKind;
  checkId: string;
  checkTitle: string;
  accountId: string;
  previousStatus?: string;
  currentStatus?: string;
  finding?: string;
  severity: DiffSeverity;
}

function accountResults(snapshot: AttestedContent, check: CheckOutput): Record<string, CheckResult> {
  return Object.keys(check.accounts ?? {}).length > 0 ? check.accounts! : { [snapshot.account_id]: check.result };
}

function setDifference(left: string[] | null | undefined, right: string[] | null | undefined): string[] {
  const prior = new Set(right ?? []);
  return [...new Set(left ?? [])].filter((value) => !prior.has(value)).sort();
}

function severity(kind: DiffEventKind, previousStatus?: string, currentStatus?: string): DiffSeverity {
  if (kind === "new_finding") return "regression";
  if (kind === "resolved_finding") return "improvement";
  if (currentStatus === "fail" || currentStatus === "error") return "regression";
  if (previousStatus === "fail" || previousStatus === "error") return "improvement";
  return "neutral";
}

/** Deterministically compare only controls and accounts both reports observed. */
export function diffReports(previous: AttestedContent, current: AttestedContent): DiffEvent[] {
  const events: DiffEvent[] = [];
  for (const [checkId, currentCheck] of Object.entries(current.checks)) {
    const previousCheck = previous.checks[checkId];
    if (!previousCheck) continue;
    const oldAccounts = accountResults(previous, previousCheck);
    const newAccounts = accountResults(current, currentCheck);
    for (const [accountId, currentResult] of Object.entries(newAccounts)) {
      const previousResult = oldAccounts[accountId];
      if (!previousResult) continue;
      if (previousResult.status !== currentResult.status) {
        events.push({
          kind: "status_changed", checkId, checkTitle: currentCheck.title, accountId,
          previousStatus: previousResult.status, currentStatus: currentResult.status,
          severity: severity("status_changed", previousResult.status, currentResult.status),
        });
      }
      for (const finding of setDifference(currentResult.findings, previousResult.findings)) {
        events.push({ kind: "new_finding", checkId, checkTitle: currentCheck.title, accountId, finding, severity: "regression" });
      }
      for (const finding of setDifference(previousResult.findings, currentResult.findings)) {
        events.push({ kind: "resolved_finding", checkId, checkTitle: currentCheck.title, accountId, finding, severity: "improvement" });
      }
    }
  }
  const rank: Record<DiffSeverity, number> = { regression: 0, neutral: 1, improvement: 2 };
  return events.sort((a, b) =>
    rank[a.severity] - rank[b.severity] || a.checkId.localeCompare(b.checkId) ||
    a.accountId.localeCompare(b.accountId) || a.kind.localeCompare(b.kind) || (a.finding ?? "").localeCompare(b.finding ?? ""),
  );
}

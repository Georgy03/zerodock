import { describe, expect, it } from "vitest";
import { diffReports } from "./diff";
import type { AttestedContent } from "./types";

function snapshot(accounts: Record<string, { status: "pass" | "fail" | "error" | "not_in_use"; findings: string[] }>): AttestedContent {
  return {
    account_id: "root", scope_verified: true, time_verified: true,
    requested_regions: [], scanned_regions: [], checks: {
      "aws.ebs.encryption": { title: "EBS encryption", tier: "provider_attested", result: { status: "pass", count: 0, findings: [] }, accounts: Object.fromEntries(Object.entries(accounts).map(([id, result]) => [id, { ...result, count: 0 }])) },
    },
  };
}

describe("diffReports", () => {
  it("mirrors the deterministic status and finding transitions", () => {
    const previous = snapshot({ "111": { status: "pass", findings: [] }, "222": { status: "fail", findings: ["old", "resolved"] } });
    const current = snapshot({ "111": { status: "fail", findings: ["new"] }, "222": { status: "pass", findings: ["old"] } });
    expect(diffReports(previous, current)).toMatchObject([
      { kind: "new_finding", accountId: "111", finding: "new", severity: "regression" },
      { kind: "status_changed", accountId: "111", previousStatus: "pass", currentStatus: "fail", severity: "regression" },
      { kind: "resolved_finding", accountId: "222", finding: "resolved", severity: "improvement" },
      { kind: "status_changed", accountId: "222", previousStatus: "fail", currentStatus: "pass", severity: "improvement" },
    ]);
  });
});

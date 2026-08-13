import { describe, expect, it } from "vitest";
import { detectScopeEvents, formatCoverageRatio, formatTimelineCoverage, isOrganizationAwareSnapshot, type AccountsSnapshot } from "./scope";

describe("detectScopeEvents", () => {
  it("returns no events when there is no prior scan", () => {
    const current: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111", "222"] };
    expect(detectScopeEvents(null, current)).toEqual([]);
  });

  it("detects a new account with no scanner role, and the coverage drop it causes", () => {
    const previous: AccountsSnapshot = { listed: ["111"], scanned: ["111"] };
    const current: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111"] };

    const events = detectScopeEvents(previous, current);
    expect(events).toContainEqual({ kind: "account_added", accountId: "222", scannerRolePresent: false });
    expect(events).toContainEqual({
      kind: "coverage_decreased",
      previousScanned: 1,
      previousListed: 1,
      currentScanned: 1,
      currentListed: 2,
    });
  });

  it("detects a new account that already has a scanner role, with no coverage drop", () => {
    const previous: AccountsSnapshot = { listed: ["111"], scanned: ["111"] };
    const current: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111", "222"] };

    const events = detectScopeEvents(previous, current);
    expect(events).toEqual([{ kind: "account_added", accountId: "222", scannerRolePresent: true }]);
  });

  it("detects an account being removed", () => {
    const previous: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111", "222"] };
    const current: AccountsSnapshot = { listed: ["111"], scanned: ["111"] };

    expect(detectScopeEvents(previous, current)).toEqual([{ kind: "account_removed", accountId: "222" }]);
  });

  it("the differentiator case: 18/18 becoming 18/19 is coverage_decreased even though the scanned count is unchanged", () => {
    const listed18 = Array.from({ length: 18 }, (_, i) => `acct-${i}`);
    const previous: AccountsSnapshot = { listed: listed18, scanned: listed18 };
    const current: AccountsSnapshot = { listed: [...listed18, "acct-new"], scanned: listed18 };

    const events = detectScopeEvents(previous, current);
    const coverageEvent = events.find((e) => e.kind === "coverage_decreased");
    expect(coverageEvent).toEqual({
      kind: "coverage_decreased",
      previousScanned: 18,
      previousListed: 18,
      currentScanned: 18,
      currentListed: 19,
    });
  });

  it("does not report improved coverage as an event", () => {
    const previous: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111"] };
    const current: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111", "222"] };

    expect(detectScopeEvents(previous, current)).toEqual([]);
  });

  it("reports nothing for an unchanged snapshot", () => {
    const snapshot: AccountsSnapshot = { listed: ["111", "222"], scanned: ["111", "222"] };
    expect(detectScopeEvents({ ...snapshot }, { ...snapshot })).toEqual([]);
  });
});

describe("formatCoverageRatio", () => {
  it("formats scanned/listed", () => {
    expect(formatCoverageRatio({ listed: ["a", "b", "c"], scanned: ["a", "b"] })).toBe("2 / 3");
  });
});

describe("organization-aware timeline coverage", () => {
  it("labels a legacy empty inventory as no organization, not 0 / 0 coverage", () => {
    const legacy: AccountsSnapshot = { listed: [], scanned: [] };
    expect(isOrganizationAwareSnapshot(legacy, undefined, undefined)).toBe(false);
    expect(formatTimelineCoverage(legacy, undefined, undefined)).toBe("No organization configured");
  });

  it("uses a ratio only for independently verified organization scope", () => {
    const organization: AccountsSnapshot = { listed: ["a", "b"], scanned: ["a"] };
    expect(isOrganizationAwareSnapshot(organization, true, false)).toBe(true);
    expect(formatTimelineCoverage(organization, true, false)).toBe("1 / 2");
  });
});

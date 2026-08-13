import { describe, expect, it } from "vitest";
import { summarizeAzureCoverage, summarizeCoverage, summarizeGCPCoverage } from "./coverage";

describe("summarizeCoverage", () => {
  it("produces the signed organization-wide 18 of 18 headline", () => {
    const accounts = Array.from({ length: 18 }, (_, index) => String(index + 1).padStart(12, "0"));
    const summary = summarizeCoverage({
      organization_verified: true,
      org_id: "o-example",
      accounts_listed: accounts,
      accounts_scanned: accounts,
    });

    expect(summary).toMatchObject({ known: true, scanned: 18, listed: 18 });
    expect(summary.note).toContain("Complete AWS Organization coverage verified");
  });

  it("does not invent a denominator when enumeration failed", () => {
    const summary = summarizeCoverage({
      organization_verified: false,
      organization_warning: "AccessDenied",
      accounts_scanned: ["111111111111"],
    });

    expect(summary.known).toBe(false);
    expect(summary.note).toBe("AccessDenied");
  });
});

describe("summarizeAzureCoverage", () => {
  it("keeps Azure subscriptions as a third independent denominator", () => {
    const summary = summarizeAzureCoverage({ azure_management_groups: ["root"], azure_subscriptions_listed: ["a", "b"], azure_subscriptions_scanned: ["a", "b"] });
    expect(summary).toMatchObject({ known: true, scanned: 2, listed: 2 });
  });
});

describe("summarizeGCPCoverage", () => {
  it("keeps the GCP project denominator independent from AWS account coverage", () => {
    const summary = summarizeGCPCoverage({
      gcp_organization_id: "123456789",
      gcp_projects_listed: ["one", "two", "three", "four"],
      gcp_projects_scanned: ["one", "two", "three", "four"],
    });
    expect(summary).toMatchObject({ known: true, scanned: 4, listed: 4 });
    expect(summary?.note).toContain("GCP Organization");
  });
});

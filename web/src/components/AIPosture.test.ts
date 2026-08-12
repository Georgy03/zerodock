import { describe, expect, it } from "vitest";
import type { CheckOutput, ShareResponse } from "../verify/types";
import { deriveAIPosture } from "./deriveAIPosture";

function check(status: CheckOutput["result"]["status"], count = 0, findings: string[] = []): CheckOutput {
  return {
    title: "test",
    tier: "provider_attested",
    result: { status, count, findings },
  };
}

describe("deriveAIPosture", () => {
  it("separates absent persistent resources from unverifiable ad-hoc Bedrock use", () => {
    const logging = check("fail", 2, ["Bedrock model invocation logging is disabled"]);
    logging.accounts = {
      "111111111111": { status: "fail", count: 1, findings: ["us-east-1: Bedrock model invocation logging is disabled"] },
      "222222222222": { status: "fail", count: 1, findings: ["us-east-1: Bedrock model invocation logging is disabled"] },
    };
    const resp = {
      accounts_scanned: ["111111111111", "222222222222"],
      checks: {
        "aws.sagemaker.endpoint_encryption": check("not_in_use"),
        "aws.sagemaker.notebook_encryption": check("not_in_use"),
        "aws.bedrock.customization_jobs": check("not_in_use"),
        "aws.bedrock.invocation_logging": logging,
        "aws.bedrock.model_access": check("not_in_use"),
      },
    } as unknown as ShareResponse;

    const summary = deriveAIPosture(resp);
    expect(summary.heading).toBe("No persistent AI/ML resources observed");
    expect(summary.resources).toContain("2 of 2 scanned accounts");
    expect(summary.resources).toContain("No Bedrock customization jobs");
    expect(summary.logging).toContain("disabled in 2 of 2");
    expect(summary.logging).toContain("cannot be ruled out");
    expect(summary.tone).toBe("attention");
  });

  it("does not call a detected endpoint a no-AI state", () => {
    const resp = {
      accounts_scanned: ["111111111111"],
      checks: {
        "aws.sagemaker.endpoint_encryption": check("pass", 1),
        "aws.sagemaker.notebook_encryption": check("not_in_use"),
        "aws.bedrock.customization_jobs": check("not_in_use"),
        "aws.bedrock.invocation_logging": check("pass", 1),
        "aws.bedrock.model_access": check("pass", 1),
      },
    } as unknown as ShareResponse;

    const summary = deriveAIPosture(resp);
    expect(summary.heading).toBe("AI/ML resources detected");
    expect(summary.agreements).toContain("1 active third-party");
  });
});

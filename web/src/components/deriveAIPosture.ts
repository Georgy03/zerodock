import type { CheckOutput, ShareResponse } from "../verify/types";

const PERSISTENT_RESOURCE_CHECKS = [
  "aws.sagemaker.endpoint_encryption",
  "aws.sagemaker.notebook_encryption",
  "aws.bedrock.customization_jobs",
] as const;

function resultForAccounts(check: CheckOutput | undefined) {
  const accountResults = Object.values(check?.accounts ?? {});
  return accountResults.length > 0 ? accountResults : check ? [check.result] : [];
}

export interface AIPostureSummary {
  heading: string;
  tone: "clear" | "attention" | "incomplete";
  resources: string;
  logging: string;
  agreements: string;
}

/**
 * Derive one buyer-readable AI conclusion exclusively from fields inside the
 * attested content. The roll-up deliberately distinguishes persistent AWS
 * resources from ad-hoc Bedrock calls, which cannot be ruled out when model
 * invocation logging is disabled.
 */
export function deriveAIPosture(resp: ShareResponse): AIPostureSummary {
  const scanned = Math.max(resp.accounts_scanned?.length ?? 0, 1);
  const persistent = PERSISTENT_RESOURCE_CHECKS.map((id) => resp.checks[id]).filter(Boolean) as CheckOutput[];
  const hasPersistentResources = persistent.some((check) => check.result.count > 0);
  const inventoryIncomplete = persistent.length !== PERSISTENT_RESOURCE_CHECKS.length ||
    persistent.some((check) => check.result.status === "error");

  let heading = "No persistent AI/ML resources observed";
  let tone: AIPostureSummary["tone"] = "clear";
  if (hasPersistentResources) {
    heading = "AI/ML resources detected";
    tone = "attention";
  } else if (inventoryIncomplete) {
    heading = "AI/ML resource inventory incomplete";
    tone = "incomplete";
  }

  const endpoint = resp.checks["aws.sagemaker.endpoint_encryption"];
  const notebook = resp.checks["aws.sagemaker.notebook_encryption"];
  const jobs = resp.checks["aws.bedrock.customization_jobs"];
  const noSageMaker = endpoint?.result.status === "not_in_use" && notebook?.result.status === "not_in_use";
  const noJobs = jobs?.result.status === "not_in_use";
  const resourceParts = [
    noSageMaker
      ? `No SageMaker endpoints or notebooks in ${scanned} of ${scanned} scanned accounts.`
      : "SageMaker resources or incomplete SageMaker inventory are shown below.",
    noJobs
      ? "No Bedrock customization jobs were observed."
      : "Bedrock customization jobs or incomplete job inventory are shown below.",
  ];

  const loggingCheck = resp.checks["aws.bedrock.invocation_logging"];
  const loggingResults = resultForAccounts(loggingCheck);
  const loggingDisabled = loggingResults.filter((result) =>
    (result.findings ?? []).some((finding) => finding.includes("invocation logging is disabled")),
  ).length;
  let logging: string;
  if (!loggingCheck || loggingResults.some((result) => result.status === "error")) {
    logging = "Bedrock invocation logging could not be fully verified, so ad-hoc model calls cannot be ruled out.";
    tone = "incomplete";
  } else if (loggingDisabled > 0) {
    logging = `Bedrock invocation logging is disabled in ${loggingDisabled} of ${loggingResults.length || scanned} scanned accounts, so ad-hoc model calls cannot be ruled out.`;
    if (tone === "clear") tone = "attention";
  } else if (loggingCheck.result.status === "fail") {
    logging = "Bedrock invocation logging is configured, but its destination has security findings shown below. Invocation telemetry may not be adequately protected.";
    if (tone === "clear") tone = "attention";
  } else {
    logging = "Bedrock invocation logging is enabled. This proves telemetry is configured; this report does not inspect prompt-log contents or claim which models were invoked.";
  }

  const agreementCount = resp.checks["aws.bedrock.model_access"]?.result.count ?? 0;
  const agreements = agreementCount === 0
    ? "No active third-party Bedrock model agreements were found. Agreements are access inventory, not usage evidence."
    : `${agreementCount} active third-party Bedrock model agreement${agreementCount === 1 ? "" : "s"} found. Agreements are access inventory, not usage evidence.`;

  return { heading, tone, resources: resourceParts.join(" "), logging, agreements };
}

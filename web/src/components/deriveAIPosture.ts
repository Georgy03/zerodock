import type { CheckOutput, ShareResponse } from "../verify/types";

const PERSISTENT_RESOURCE_CHECKS = [
  "aws.sagemaker.endpoint_encryption",
  "aws.sagemaker.notebook_encryption",
  "aws.bedrock.customization_jobs",
  "aws.bedrock.agent_permissions",
  "aws.bedrock.knowledge_base_exposure",
  "aws.sagemaker.network_isolation",
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
  execute: string;
  retrieve: string;
  egress: string;
}

/**
 * Derive one buyer-readable AI conclusion exclusively from fields inside the
 * attested content. The roll-up deliberately distinguishes persistent AWS
 * resources from ad-hoc Bedrock calls, which cannot be ruled out when model
 * invocation logging is disabled.
 */
export function deriveAIPosture(resp: ShareResponse): AIPostureSummary {
  const scanned = Math.max(resp.accounts_scanned?.length ?? 0, 1);
  // New controls are optional here so previously attested reports remain
  // interpretable; absence means the scanner version predates the control,
  // not that current inventory is necessarily incomplete.
  const persistent = PERSISTENT_RESOURCE_CHECKS.map((id) => resp.checks[id]).filter(Boolean) as CheckOutput[];
  const hasPersistentResources = persistent.some((check) => check.result.count > 0);
  const inventoryIncomplete = persistent.some((check) => check.result.status === "error");

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

  const agents = resp.checks["aws.bedrock.agent_permissions"];
  const knowledgeBases = resp.checks["aws.bedrock.knowledge_base_exposure"];
  const isolation = resp.checks["aws.sagemaker.network_isolation"];
  const noAgents = agents?.result.status === "not_in_use";
  const noKnowledgeBases = knowledgeBases?.result.status === "not_in_use";
  if ([agents, knowledgeBases, isolation].some((check) => check?.result.status === "error")) tone = "incomplete";
  const agentFindings = agents?.result.findings ?? [];
  const lambdaPaths = (agents?.result.evidence ?? []).filter((line) => line.includes("invokes Lambda")).length;
  const broadAgentPermissions = agentFindings.filter((line) => line.includes("BROAD PRIVILEGE") || line.includes("BROAD RESOURCE SCOPE")).length;
  const execute = noAgents
    ? "No Bedrock agents configured."
    : `${agents?.result.count ?? 0} Bedrock agent(s), ${broadAgentPermissions} broad permission finding(s), and ${lambdaPaths} Lambda action-group path(s). Details below name every role, permission, and Lambda target.`;

  const knowledgeFindings = knowledgeBases?.result.findings ?? [];
  const s3Sources = (knowledgeBases?.result.evidence ?? []).filter((line) => line.includes("retrieves from S3")).length;
  const publicSources = knowledgeFindings.filter((line) => line.includes("HIGH: retrieves from publicly accessible S3 bucket")).length;
  const retrieve = noKnowledgeBases
    ? "No Bedrock knowledge bases configured."
    : `${knowledgeBases?.result.count ?? 0} knowledge base(s), ${s3Sources} S3 data source(s), and ${publicSources} public source bucket(s). Details below show sources, execution-role scope, and vector-store visibility.`;

  const egress = isolation?.result.status === "not_in_use"
    ? "No SageMaker workloads requiring network-isolation review were observed."
    : "SageMaker models, training jobs, processing jobs, and Studio domains are broken out below. Network isolation and VPC placement are separate evidence dimensions.";

  return { heading, tone, resources: resourceParts.join(" "), logging, agreements, execute, retrieve, egress };
}

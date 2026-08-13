import type { ShareResponse } from "./verify/types";

export class ShareFetchError extends Error {
  readonly status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

/**
 * API_BASE_URL points at the backend (internal/api's cmd/api server).
 * Configured via a Vite env var so the same build can point at different
 * backends without a code change — see .env.example in this directory.
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

export async function fetchShare(token: string): Promise<ShareResponse> {
  const res = await fetch(`${API_BASE_URL}/v1/share/${encodeURIComponent(token)}`);
  if (res.status === 404) {
    throw new ShareFetchError("This share link is unknown — it may be mistyped or never existed.", 404);
  }
  if (res.status === 410) {
    throw new ShareFetchError("This share link has been revoked by its owner.", 410);
  }
  if (!res.ok) {
    throw new ShareFetchError(`Server returned ${res.status} fetching this share link.`, res.status);
  }
  return (await res.json()) as ShareResponse;
}

export interface HistoryResponse {
  token: string;
  verdicts: ShareResponse[];
}

/**
 * fetchHistory returns every attested verdict for a token, newest first
 * — the SAME shape GET /v1/share/{token} returns per entry (full
 * attestation included), so each one can be independently re-verified
 * with verifyShareResponse rather than trusted as-is. This is what
 * verify/scope.ts's drift detection and the scope history timeline are
 * built on: signed data the browser checks itself, not a server-asserted
 * diff.
 */
export async function fetchHistory(token: string, limit?: number): Promise<HistoryResponse> {
  const query = limit ? `?limit=${encodeURIComponent(String(limit))}` : "";
  const res = await fetch(`${API_BASE_URL}/v1/share/${encodeURIComponent(token)}/history${query}`);
  if (res.status === 404) {
    throw new ShareFetchError("This share link is unknown — it may be mistyped or never existed.", 404);
  }
  if (res.status === 410) {
    throw new ShareFetchError("This share link has been revoked by its owner.", 410);
  }
  if (!res.ok) {
    throw new ShareFetchError(`Server returned ${res.status} fetching this share link's history.`, res.status);
  }
  return (await res.json()) as HistoryResponse;
}

/** Server-side convenience index for integrations; buyer-page changes are still recomputed from fetchHistory(). */
export interface ControlHistoryTransition {
  scan_id: string;
  attested_at: string;
  account_id: string;
  previous_status?: string;
  current_status: string;
}

export async function fetchControlHistory(token: string, checkId: string): Promise<{ token: string; check_id: string; transitions: ControlHistoryTransition[] }> {
  const res = await fetch(`${API_BASE_URL}/v1/share/${encodeURIComponent(token)}/history/${encodeURIComponent(checkId)}`);
  if (!res.ok) throw new ShareFetchError(`Server returned ${res.status} fetching this control's history.`, res.status);
  return (await res.json()) as { token: string; check_id: string; transitions: ControlHistoryTransition[] };
}

export interface AutofillReport {
  answered: number;
  partial: number;
  flagged: number;
  needs_human: number;
  hours_saved: number;
  rows_reviewed: number;
  framework: string;
  evidence_url: string;
  verdict_date: string;
  estimate_basis: string;
}

export interface AutofillDownload {
  blob: Blob;
  filename: string;
  report: AutofillReport;
}

export async function autofillQuestionnaire(token: string, file: File): Promise<AutofillDownload> {
  const form = new FormData();
  form.append("questionnaire", file);
  const res = await fetch(`${API_BASE_URL}/v1/share/${encodeURIComponent(token)}/questionnaires/autofill`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    let message = `Autofill failed with status ${res.status}.`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based fallback when a proxy returned non-JSON.
    }
    throw new ShareFetchError(message, res.status);
  }

  const encodedReport = res.headers.get("X-ZeroDock-Autofill-Report");
  if (!encodedReport) throw new ShareFetchError("Autofill response did not include its review report.");
  const normalized = encodedReport.replace(/-/g, "+").replace(/_/g, "/");
  const reportBytes = Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")), (char) => char.charCodeAt(0));
  const report = JSON.parse(new TextDecoder().decode(reportBytes)) as AutofillReport;
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] ?? `questionnaire-zerodock-filled${file.name.toLowerCase().endsWith(".xlsx") ? ".xlsx" : ".csv"}`;
  return { blob: await res.blob(), filename, report };
}

export interface OnboardingStart {
  tenant_id: string;
  stack_command: string;
}

export async function startOnboarding(customerAccountId: string): Promise<OnboardingStart> {
  const res = await fetch(`${API_BASE_URL}/v1/onboard`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ customer_account_id: customerAccountId }),
  });
  if (!res.ok) {
    let message = `Could not start onboarding (status ${res.status}).`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based fallback when the server returned non-JSON.
    }
    throw new ShareFetchError(message, res.status);
  }
  return (await res.json()) as OnboardingStart;
}

export interface OnboardingStatus {
  management_role_connected: boolean;
  scope_verified: boolean;
  no_organization: boolean;
  total_accounts: number;
  connected_accounts: number;
}

export async function fetchOnboardingStatus(tenantId: string): Promise<OnboardingStatus> {
  const res = await fetch(`${API_BASE_URL}/v1/onboard/${encodeURIComponent(tenantId)}/status`);
  if (!res.ok) {
    let message = `Could not check connection status (status ${res.status}).`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based fallback when the server returned non-JSON.
    }
    throw new ShareFetchError(message, res.status);
  }
  return (await res.json()) as OnboardingStatus;
}

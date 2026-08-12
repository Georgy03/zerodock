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

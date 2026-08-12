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

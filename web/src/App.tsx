import { useEffect, useState } from "react";
import "./App.css";
import { fetchShare, ShareFetchError } from "./api";
import type { ShareResponse } from "./verify/types";
import { verifyShareResponse, type VerificationResult } from "./verify/verifier";
import { StatusBanner } from "./components/StatusBanner";
import { CoverageHeadline } from "./components/CoverageHeadline";
import { ControlList } from "./components/ControlList";
import { AttestationDetails } from "./components/AttestationDetails";
import { VerificationPanel } from "./components/VerificationPanel";

/** Default freshness window: 30 days. Configurable via VITE_FRESHNESS_WINDOW_MS — see verify/freshness.ts. */
const DEFAULT_FRESHNESS_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

function freshnessWindowMs(): number {
  const raw = import.meta.env.VITE_FRESHNESS_WINDOW_MS;
  if (!raw) return DEFAULT_FRESHNESS_WINDOW_MS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_FRESHNESS_WINDOW_MS;
}

function tokenFromLocation(): string | null {
  const params = new URLSearchParams(window.location.search);
  const fromQuery = params.get("token");
  if (fromQuery) return fromQuery;

  // Fall back to the last path segment, so /share/TOKEN also works
  // without requiring a query string.
  const segments = window.location.pathname.split("/").filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : null;
}

type PageState =
  | { phase: "loading" }
  | { phase: "fetch-error"; message: string }
  | { phase: "done"; resp: ShareResponse; result: VerificationResult };

function App() {
  const [state, setState] = useState<PageState>({ phase: "loading" });

  useEffect(() => {
    const token = tokenFromLocation();
    if (!token) {
      setState({ phase: "fetch-error", message: "No share token in the URL." });
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const resp = await fetchShare(token);
        const result = await verifyShareResponse(resp, { freshnessWindowMs: freshnessWindowMs() });
        if (!cancelled) setState({ phase: "done", resp, result });
      } catch (err) {
        if (cancelled) return;
        const message = err instanceof ShareFetchError ? err.message : `Unexpected error: ${(err as Error).message}`;
        setState({ phase: "fetch-error", message });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="page">
      <header className="page__header">
        <span className="page__brand">ZeroDock</span>
        <span className="page__tagline">Verified entirely in your browser — nothing here is taken on trust.</span>
      </header>

      {state.phase === "loading" && <div className="page__loading">Fetching and verifying…</div>}

      {state.phase === "fetch-error" && (
        <div className="status-banner status-banner--failed" role="alert">
          <span className="status-banner__icon" aria-hidden>
            ✗
          </span>
          <div>
            <div className="status-banner__title">Could not load this scan</div>
            <div className="status-banner__subtitle">{state.message}</div>
          </div>
        </div>
      )}

      {state.phase === "done" && (
        <>
          <StatusBanner result={state.result} />
          <CoverageHeadline resp={state.resp} verified={state.result.status === "verified"} />
          <ControlList resp={state.resp} />
          <VerificationPanel result={state.result} />
          <AttestationDetails resp={state.resp} result={state.result} />
        </>
      )}
    </main>
  );
}

export default App;

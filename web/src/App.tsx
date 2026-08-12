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
import { QuestionnaireAutofill } from "./components/QuestionnaireAutofill";

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
        <div className="brand-lockup">
          <img className="brand-lockup__mark" src="/zerodock-mark.png" alt="" aria-hidden="true" />
          <div className="brand-lockup__type">
            <img className="brand-lockup__wordmark" src="/zerodock-wordmark.png" alt="ZeroDock" />
            <span className="brand-lockup__promise">Zero knowledge. Verified trust.</span>
          </div>
        </div>
        <div className="page__context">
          <span className="page__context-kicker">Independent assurance</span>
          <span className="page__context-copy">Cryptographically verified in this browser</span>
        </div>
      </header>

      <div className="page__brand-rule" aria-hidden><span>ZD / TRUST REPORT</span></div>

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
          <section className="page__hero" aria-label="Trust and coverage summary">
            <StatusBanner result={state.result} />
            <CoverageHeadline resp={state.resp} verified={state.result.status === "verified"} />
          </section>

          <section className="page__section">
            <div className="section-heading">
              <div>
                <span className="section-heading__index">01</span>
                <h2>Cloud posture</h2>
              </div>
              <p>Provider-attested findings across every account in scope.</p>
            </div>
            <ControlList resp={state.resp} />
          </section>

          <section className="page__section page__section--questionnaire">
            <div className="section-heading">
              <div>
                <span className="section-heading__index">02</span>
                <h2>Questionnaire autofill</h2>
              </div>
              <p>Evidence-backed answers, with unsafe claims held for human review.</p>
            </div>
            <QuestionnaireAutofill token={tokenFromLocation() ?? ""} verified={state.result.status === "verified"} />
          </section>

          <section className="page__section">
            <div className="section-heading">
              <div>
                <span className="section-heading__index">03</span>
                <h2>Proof chain</h2>
              </div>
              <p>Six checks performed locally. The API cannot mark itself verified.</p>
            </div>
            <VerificationPanel result={state.result} />
          </section>

          <section className="page__section page__section--evidence">
            <div className="section-heading">
              <div>
                <span className="section-heading__index">04</span>
                <h2>Raw evidence</h2>
              </div>
              <p>Hardware identity, release measurement, and signed report fingerprint.</p>
            </div>
            <AttestationDetails resp={state.resp} result={state.result} />
          </section>
        </>
      )}

      <footer className="page__footer">
        <img className="page__footer-mark" src="/zerodock-mark.png" alt="" aria-hidden="true" />
        <span>Zero knowledge.</span>
        <strong>Verified trust.</strong>
      </footer>
    </main>
  );
}

export default App;

import type { VerificationResult } from "../verify/verifier";

/**
 * The single most important pixel on this page: whether verification
 * succeeded. Fail-closed means this component has exactly one way to
 * render green — result.status === "verified" — and every other input,
 * including a result object that's malformed in some way we didn't
 * anticipate, renders red. There is no default-to-green fallback.
 */
export function StatusBanner({ result }: { result: VerificationResult }) {
  if (result.status === "verified") {
    return (
      <div className="status-banner status-banner--verified" role="status">
        <span className="status-banner__icon" aria-hidden>
          ✓
        </span>
        <div>
          <div className="status-banner__title">Verified — hardware-attested</div>
          <div className="status-banner__subtitle">
            All report checks passed entirely in this browser. Historical changes, when available, are independently
            verified and recomputed below — nothing came on trust from the server.
          </div>
        </div>
      </div>
    );
  }

  const firstFailure = result.checks.find((c) => !c.passed);
  return (
    <div className="status-banner status-banner--failed" role="alert">
      <span className="status-banner__icon" aria-hidden>
        ✗
      </span>
      <div>
        <div className="status-banner__title">NOT VERIFIED</div>
        <div className="status-banner__subtitle">
          {firstFailure ? `${firstFailure.label} failed: ${firstFailure.detail}` : "Verification did not complete."}
        </div>
      </div>
    </div>
  );
}

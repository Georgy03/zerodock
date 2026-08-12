import { useState } from "react";
import type { VerificationResult } from "../verify/verifier";

/** Expandable panel: all client-side checks, pass/fail, and what each one actually did. */
export function VerificationPanel({ result }: { result: VerificationResult }) {
  const [open, setOpen] = useState(result.status === "failed");

  return (
    <section className="verification-panel">
      <button
        type="button"
        className="verification-panel__toggle"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        {open ? "▾" : "▸"} Verification details ({result.checks.filter((c) => c.passed).length}/
        {result.checks.length} checks passed — verified entirely in your browser)
      </button>
      {open && (
        <ol className="verification-panel__list">
          {result.checks.map((check) => (
            <li key={check.name} className={`verification-check verification-check--${check.passed ? "pass" : "fail"}`}>
              <div className="verification-check__header">
                <span className="status-dot" aria-hidden>
                  {check.passed ? "✓" : "✗"}
                </span>
                <span className="verification-check__label">{check.label}</span>
              </div>
              <div className="verification-check__detail">{check.detail}</div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

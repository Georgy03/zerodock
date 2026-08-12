import type { ShareResponse } from "../verify/types";
import { summarizeCoverage } from "./coverage";

/**
 * Coverage means accounts scanned out of accounts that exist. The current
 * single-account report cannot know the organization-wide denominator yet,
 * so say that plainly instead of substituting an unrelated control score.
 */
export function CoverageHeadline({ resp, verified }: { resp: ShareResponse; verified: boolean }) {
  const coverage = summarizeCoverage(resp);

  return (
    <div className={`coverage-headline${verified ? "" : " coverage-headline--unverified"}`}>
      {!verified && <div className="coverage-headline__warning">UNVERIFIED — do not rely on this report</div>}
      <div className="coverage-headline__eyebrow">Account coverage</div>
      {coverage.known ? (
        <div className="coverage-headline__ratio">
          {coverage.scanned}
          <span className="coverage-headline__ratio-sep">/</span>
          {coverage.listed}
        </div>
      ) : (
        <div className="coverage-headline__account">Coverage unknown</div>
      )}
      <div className="coverage-headline__label">accounts scanned</div>
      <div className="coverage-headline__note">{coverage.note}</div>
    </div>
  );
}

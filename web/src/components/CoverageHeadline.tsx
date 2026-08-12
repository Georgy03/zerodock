import type { ShareResponse } from "../verify/types";

/**
 * Coverage means accounts scanned out of accounts that exist. The current
 * single-account report cannot know the organization-wide denominator yet,
 * so say that plainly instead of substituting an unrelated control score.
 */
export function CoverageHeadline({ resp, verified }: { resp: ShareResponse; verified: boolean }) {
  return (
    <div className={`coverage-headline${verified ? "" : " coverage-headline--unverified"}`}>
      {!verified && <div className="coverage-headline__warning">UNVERIFIED — do not rely on this report</div>}
      <div className="coverage-headline__eyebrow">Account coverage</div>
      <div className="coverage-headline__account">1 AWS account scanned</div>
      <div className="coverage-headline__label">{resp.account_id}</div>
      <div className="coverage-headline__note">
        Organization account enumeration is not available yet, so total account coverage is unknown.
      </div>
    </div>
  );
}

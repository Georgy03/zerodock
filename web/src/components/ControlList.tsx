import type { ShareResponse } from "../verify/types";

const TIER_LABEL: Record<string, string> = {
  provider_attested: "Provider-attested",
  actively_probed: "Actively probed",
  infra_only: "Infra only",
};

const TIER_HINT: Record<string, string> = {
  provider_attested: "AWS itself is asserting this fact.",
  actively_probed: "Tested with a live network challenge against the resource.",
  infra_only: "Cloud-API-verified envelope; internals unverified.",
};

/**
 * Every control the scan ran, with its result AND its evidence tier —
 * tier is shown per-claim, not just buried in a tooltip, because it's
 * the thing that tells a reader how much to trust a specific line, not
 * just the scan as a whole. See internal/checks.Tier's doc comment on
 * the Go side for what each tier actually means.
 */
export function ControlList({ resp }: { resp: ShareResponse }) {
  const entries = Object.entries(resp.checks).sort(([a], [b]) => a.localeCompare(b));

  return (
    <ul className="control-list">
      {entries.map(([id, check]) => (
        <li key={id} className={`control-item control-item--${check.result.status}`}>
          <div className="control-item__header">
            <span className={`status-dot status-dot--${check.result.status}`} aria-hidden />
            <span className="control-item__title">{check.title}</span>
            <span className="control-item__id">{id}</span>
            <span className="tier-badge" title={TIER_HINT[check.tier] ?? ""}>
              {TIER_LABEL[check.tier] ?? check.tier}
            </span>
          </div>
          {check.result.findings && check.result.findings.length > 0 && (
            <ul className="control-item__findings">
              {check.result.findings.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          )}
          <div className="control-item__meta">
            {check.result.count} resource{check.result.count === 1 ? "" : "s"} examined
            {check.result.region ? ` in ${check.result.region}` : ""}
          </div>
        </li>
      ))}
    </ul>
  );
}

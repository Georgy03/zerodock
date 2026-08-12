import type { ShareResponse } from "../verify/types";
import type { VerificationResult } from "../verify/verifier";
import { buildPCRDisplayRows } from "./pcrDisplay";

/** Raw attestation facts, in monospace, at the bottom — the "show your work" section. */
export function AttestationDetails({ resp, result }: { resp: ShareResponse; result: VerificationResult }) {
  const doc = result.document;

  return (
    <section className="attestation-details">
      <h2>Attestation details</h2>
      <dl className="mono-fields">
        <dt>Format</dt>
        <dd>{resp.attestation.format}</dd>

        <dt>Scanner version</dt>
        <dd>{resp.scanner_version ?? "(legacy report — not recorded)"}</dd>

        <dt>Mock</dt>
        <dd>{resp.attestation.mock ? "true — NOT hardware-backed" : "false"}</dd>

        <dt>Scan ID</dt>
        <dd>{resp.scan_id}</dd>

        <dt>Account</dt>
        <dd>{resp.account_id}</dd>

        <dt>Attested at</dt>
        <dd>{resp.attested_at}</dd>

        <dt>Module ID</dt>
        <dd>{doc?.payload.module_id ?? "(document not decoded)"}</dd>

        <dt>Leaf certificate subject</dt>
        <dd>{result.leafSubject ?? "(unavailable)"}</dd>

        <dt>Root certificate subject</dt>
        <dd>{result.rootSubject ?? "(unavailable)"}</dd>

        <dt>Results SHA-384</dt>
        <dd className="mono-fields__wrap">{resp.results_sha384}</dd>

        {buildPCRDisplayRows(resp.attestation.pcrs).map((row) => (
          <FragmentPCR key={row.key} label={row.label} value={row.value} collapsed={row.collapsed} />
        ))}
      </dl>
    </section>
  );
}

function FragmentPCR({ label, value, collapsed }: { label: string; value: string; collapsed: boolean }) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={collapsed ? undefined : "mono-fields__wrap"}>{value}</dd>
    </>
  );
}

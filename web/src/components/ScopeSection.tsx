import { useEffect, useMemo, useState } from "react";
import { fetchHistory } from "../api";
import { recomputeAttestedDiff, verifyShareResponse, type CheckOutcome } from "../verify/verifier";
import { detectScopeEvents, formatTimelineCoverage, isOrganizationAwareSnapshot, type AccountsSnapshot, type ScopeEvent } from "../verify/scope";
import type { DiffEvent, DiffSeverity } from "../verify/diff";
import type { ShareResponse } from "../verify/types";

const TIMELINE_LENGTH = 10;

interface VerifiedEntry { resp: ShareResponse; snapshot: AccountsSnapshot }
type State =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "ready"; verified: VerifiedEntry[]; unverifiedCount: number };

function snapshotOf(resp: ShareResponse): AccountsSnapshot {
  return { listed: resp.accounts_listed ?? [], scanned: resp.accounts_scanned ?? [] };
}

/**
 * Buyer-facing, locally verified transition view. The API supplies complete
 * historical documents, never a claimed delta; every entry is re-verified
 * before diffing and any failed entry is excluded. Historical freshness is
 * intentionally skipped because authenticity, not recency, is what matters
 * when comparing an older baseline to a newer attested report.
 */
export function ScopeSection({ token, onDiffCheck }: { token: string; onDiffCheck: (check: CheckOutcome) => void }) {
  const [state, setState] = useState<State>({ phase: "loading" });
  const [selected, setSelected] = useState<[string, string] | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const history = await fetchHistory(token, 100);
        const verified: VerifiedEntry[] = [];
        let unverifiedCount = 0;
        for (const resp of history.verdicts) {
          const result = await verifyShareResponse(resp, { freshnessWindowMs: 0, skipFreshness: true });
          if (result.status === "verified") verified.push({ resp, snapshot: snapshotOf(resp) });
          else unverifiedCount++;
        }
        if (!cancelled) setState({ phase: "ready", verified, unverifiedCount });
      } catch (err) {
        if (!cancelled) {
          setState({ phase: "error", message: (err as Error).message });
          onDiffCheck({ name: "diff", label: "Recompute changes from attested snapshots", passed: false, detail: "Diff was not rendered: historical snapshots could not be verified." });
        }
      }
    })();
    return () => { cancelled = true; };
  }, [token, onDiffCheck]);

  const pair = useMemo(() => {
    if (state.phase !== "ready" || state.verified.length < 2) return null;
    const defaults: [string, string] = [state.verified[0].resp.scan_id, state.verified[1].resp.scan_id];
    const wanted = selected ?? defaults;
    const first = state.verified.findIndex((entry) => entry.resp.scan_id === wanted[0]);
    const second = state.verified.findIndex((entry) => entry.resp.scan_id === wanted[1]);
    if (first < 0 || second < 0 || first === second) return null;
    // History is newest-first, so the smaller index is the current side.
    return first < second ? { current: state.verified[first], previous: state.verified[second], ids: wanted } : { current: state.verified[second], previous: state.verified[first], ids: [wanted[1], wanted[0]] as [string, string] };
  }, [state, selected]);

  const diff = useMemo(
    () => pair ? recomputeAttestedDiff(pair.previous.resp, pair.current.resp) : null,
    [pair],
  );
  useEffect(() => {
    if (diff) onDiffCheck(diff.check);
    else if (state.phase === "ready") onDiffCheck({ name: "diff", label: "Recompute changes from attested snapshots", passed: false, detail: "Not run: at least two independently verified scans are required." });
  }, [diff, state.phase, onDiffCheck]);

  if (state.phase === "loading") return <div className="scope-section scope-section--loading">Verifying scan history before computing changes…</div>;
  if (state.phase === "error") return <div className="scope-section scope-section--error">Could not verify scan history: {state.message}</div>;
  if (state.verified.length === 0) return null;

  return (
    <section className="scope-section" aria-label="Changes between verified scans">
      <div className="scope-events scope-events--baseline">
        <strong>{pair ? "Changes between verified scans" : "Changes require a second verified scan"}</strong>
        <p>SOC 2 records what auditors observed during an audit period. This is additive evidence of what changed since — not a replacement for SOC 2.</p>
      </div>
      {state.verified.length > 1 && (
        <ScanPicker entries={state.verified} selected={pair?.ids ?? null} onChange={setSelected} />
      )}
      {pair && diff && diff.check.passed && <ChangeGroups events={diff.events} scopeEvents={detectScopeEvents(pair.previous.snapshot, pair.current.snapshot)} observedAt={pair.current.resp.attested_at} />}
      {state.verified.length > 1 && <ScopeTimeline entries={state.verified} />}
      {state.unverifiedCount > 0 && <p className="scope-section__unverified">{state.unverifiedCount} historical {state.unverifiedCount === 1 ? "entry" : "entries"} failed independent verification and were excluded.</p>}
    </section>
  );
}

function ScanPicker({ entries, selected, onChange }: { entries: VerifiedEntry[]; selected: [string, string] | null; onChange: (pair: [string, string]) => void }) {
  const value = selected ?? [entries[0].resp.scan_id, entries[1].resp.scan_id];
  return <div className="scope-picker">
    <label>Later scan <select value={value[0]} onChange={(event) => onChange([event.target.value, value[1]])}>{entries.map((entry) => <option key={entry.resp.scan_id} value={entry.resp.scan_id}>{new Date(entry.resp.attested_at).toLocaleString()}</option>)}</select></label>
    <label>Earlier scan <select value={value[1]} onChange={(event) => onChange([value[0], event.target.value])}>{entries.map((entry) => <option key={entry.resp.scan_id} value={entry.resp.scan_id}>{new Date(entry.resp.attested_at).toLocaleString()}</option>)}</select></label>
  </div>;
}

type PresentedChange = { severity: DiffSeverity; key: string; content: string };
function ChangeGroups({ events, scopeEvents, observedAt }: { events: DiffEvent[]; scopeEvents: ScopeEvent[]; observedAt: string }) {
  const changes: PresentedChange[] = [
    ...events.map((event) => ({ severity: event.severity, key: `${event.checkId}:${event.accountId}:${event.kind}:${event.finding ?? ""}`, content: diffText(event) })),
    ...scopeEvents.map((event, index) => ({ severity: scopeSeverity(event), key: `${event.kind}:${event.accountId ?? index}`, content: scopeText(event) })),
  ];
  const groups: [DiffSeverity, string][] = [["regression", "Needs attention"], ["neutral", "Scope and status changes"], ["improvement", "Resolved or improved"]];
  return <div className="change-groups">
    {changes.length === 0 && <p className="change-groups__empty">No reportable control, finding, or coverage transitions between these two verified scans.</p>}
    {groups.map(([severity, label]) => {
      const items = changes.filter((change) => change.severity === severity);
      return items.length === 0 ? null : <div key={severity} className={`change-group change-group--${severity}`}><h3>{label}</h3><ul>{items.map((item) => <li key={item.key}>{item.content}<small>First observed: {new Date(observedAt).toLocaleString()}</small></li>)}</ul></div>;
    })}
  </div>;
}

function diffText(event: DiffEvent): string {
  const subject = `${event.checkTitle} (${event.checkId}) in account ${event.accountId}`;
  if (event.kind === "status_changed") return `${subject}: ${event.previousStatus} → ${event.currentStatus}.`;
  return `${subject}: ${event.kind === "new_finding" ? "new finding" : "finding resolved"} — ${event.finding}.`;
}
function scopeSeverity(event: ScopeEvent): DiffSeverity {
  return event.kind === "coverage_decreased" || (event.kind === "account_added" && !event.scannerRolePresent) ? "regression" : "neutral";
}
function scopeText(event: ScopeEvent): string {
  if (event.kind === "coverage_decreased") return `Coverage decreased: ${event.previousScanned}/${event.previousListed} → ${event.currentScanned}/${event.currentListed}.`;
  if (event.kind === "account_added") return `Account ${event.accountId} was added (${event.scannerRolePresent ? "scanner role present" : "scanner role not present"}).`;
  return `Account ${event.accountId} is no longer listed.`;
}

function ScopeTimeline({ entries }: { entries: VerifiedEntry[] }) {
  const chronological = [...entries].reverse().slice(-TIMELINE_LENGTH);
  return <div className="scope-timeline"><div className="scope-timeline__heading"><span className="scope-timeline__label">Coverage ratio across the last {chronological.length} verified scans</span><span className="scope-timeline__direction">Oldest → newest (now)</span></div><ol className="scope-timeline__list">{chronological.map((entry, i) => {
    const prior = chronological[i - 1];
    const organizationAware = isOrganizationAwareSnapshot(entry.snapshot, entry.resp.organization_verified, entry.resp.no_organization);
    const priorOrganizationAware = prior && isOrganizationAwareSnapshot(prior.snapshot, prior.resp.organization_verified, prior.resp.no_organization);
    const dropped = !!priorOrganizationAware && organizationAware && entry.snapshot.scanned.length / entry.snapshot.listed.length < prior.snapshot.scanned.length / prior.snapshot.listed.length;
    return <li key={entry.resp.scan_id} className={`scope-timeline__point${!organizationAware ? " scope-timeline__point--no-org" : ""}${dropped ? " scope-timeline__point--dropped" : ""}`}><span className="scope-timeline__ratio">{formatTimelineCoverage(entry.snapshot, entry.resp.organization_verified, entry.resp.no_organization)}</span><span className="scope-timeline__date">{new Date(entry.resp.attested_at).toLocaleDateString()}</span>{dropped && <span className="scope-timeline__flag" title="Coverage dropped versus the previous scan">▼</span>}</li>;
  })}</ol></div>;
}

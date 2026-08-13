import { useEffect, useRef, useState } from "react";
import "./App.css";
import { fetchOnboardingStatus, startOnboarding, type OnboardingStatus } from "./api";

const ACCOUNT_ID_PATTERN = /^[0-9]{12}$/;
const POLL_INTERVAL_MS = 5000;

type Phase =
  | { step: "enter-account" }
  | { step: "starting" }
  | { step: "start-error"; message: string }
  | { step: "connecting"; tenantId: string; command: string; status: OnboardingStatus | null; pollError: string | null };

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="onboard-command">
      <pre>
        <code>{command}</code>
      </pre>
      <button
        type="button"
        onClick={async () => {
          await navigator.clipboard.writeText(command);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
      >
        {copied ? "Copied" : "Copy command"}
      </button>
    </div>
  );
}

function ConnectionCounter({ status }: { status: OnboardingStatus | null }) {
  if (!status || !status.management_role_connected) {
    return (
      <div className="onboard-counter onboard-counter--waiting">
        Waiting for the management-account role to connect… this updates automatically once AWS finishes
        creating it (usually under a minute after the command above completes).
      </div>
    );
  }

  if (status.no_organization) {
    return (
      <div className="onboard-counter onboard-counter--single">
        <strong>1 of 1 accounts connected</strong>
        <span className="onboard-counter__badge">Unverified scope</span>
        <p>
          This AWS account is not part of an AWS Organization, so ZeroDock cannot confirm there are no other
          accounts to cover. Every scan of this connection will carry the same unverified-scope label.
        </p>
      </div>
    );
  }

  const { connected_accounts, total_accounts } = status;
  const done = connected_accounts >= total_accounts && total_accounts > 0;
  return (
    <div className={`onboard-counter${done ? " onboard-counter--done" : ""}`}>
      <strong>
        {connected_accounts} of {total_accounts} accounts connected
      </strong>
      {!done && <p>New accounts connect automatically as the StackSet finishes rolling out across your organization.</p>}
      {done && <p>Every account AWS Organizations reported for this org is connected.</p>}
    </div>
  );
}

export function OnboardPage() {
  const [phase, setPhase] = useState<Phase>({ step: "enter-account" });
  const [accountIdInput, setAccountIdInput] = useState("");
  const pollTimer = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
  }, []);

  useEffect(() => {
    if (phase.step !== "connecting") return;
    const tenantId = phase.tenantId;

    let cancelled = false;
    async function poll() {
      try {
        const status = await fetchOnboardingStatus(tenantId);
        if (cancelled) return;
        setPhase((prev) => (prev.step === "connecting" ? { ...prev, status, pollError: null } : prev));
      } catch (err) {
        if (cancelled) return;
        setPhase((prev) =>
          prev.step === "connecting" ? { ...prev, pollError: (err as Error).message } : prev,
        );
      } finally {
        if (!cancelled) pollTimer.current = window.setTimeout(poll, POLL_INTERVAL_MS);
      }
    }
    poll();

    return () => {
      cancelled = true;
      if (pollTimer.current !== null) window.clearTimeout(pollTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase.step === "connecting" ? phase.tenantId : null]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!ACCOUNT_ID_PATTERN.test(accountIdInput)) return;
    setPhase({ step: "starting" });
    try {
      const { tenant_id, stack_command } = await startOnboarding(accountIdInput);
      setPhase({ step: "connecting", tenantId: tenant_id, command: stack_command, status: null, pollError: null });
    } catch (err) {
      setPhase({ step: "start-error", message: (err as Error).message });
    }
  }

  return (
    <main className="onboard-page">
      <header className="onboard-page__header">
        <h1>Connect your AWS account</h1>
        <p>ZeroDock scans read-only, from inside a hardware-attested Nitro enclave. Nothing here grants write access.</p>
      </header>

      {(phase.step === "enter-account" || phase.step === "starting" || phase.step === "start-error") && (
        <form className="onboard-form" onSubmit={handleSubmit}>
          <label htmlFor="account-id">Your AWS account ID</label>
          <input
            id="account-id"
            inputMode="numeric"
            pattern="[0-9]{12}"
            placeholder="123456789012"
            value={accountIdInput}
            onChange={(e) => setAccountIdInput(e.target.value.trim())}
            disabled={phase.step === "starting"}
          />
          <p className="onboard-form__hint">
            If this account is an AWS Organizations management account, ZeroDock will detect and connect every
            account in the organization automatically. Otherwise it connects this one account only.
          </p>
          <button type="submit" disabled={phase.step === "starting" || !ACCOUNT_ID_PATTERN.test(accountIdInput)}>
            {phase.step === "starting" ? "Starting…" : "Generate connection command"}
          </button>
          {phase.step === "start-error" && <p className="onboard-form__error">{phase.message}</p>}
        </form>
      )}

      {phase.step === "connecting" && (
        <div className="onboard-connect">
          <ol className="onboard-steps">
            <li>
              Run this command with AWS credentials for account <strong>{accountIdInput}</strong> (the AWS CLI must
              already be configured — <code>aws configure</code> — with sufficient permissions to create IAM roles
              and, if this is a management account, CloudFormation StackSets):
              <CopyCommand command={phase.command} />
            </li>
            <li>Leave this page open. The counter below updates automatically.</li>
          </ol>
          <ConnectionCounter status={phase.status} />
          {phase.pollError && <p className="onboard-form__error">{phase.pollError}</p>}
        </div>
      )}
    </main>
  );
}

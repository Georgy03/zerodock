import { useRef, useState } from "react";
import { autofillQuestionnaire, type AutofillReport } from "../api";

interface QuestionnaireAutofillProps {
  token: string;
  verified: boolean;
}

type UploadState =
  | { phase: "idle" }
  | { phase: "running" }
  | { phase: "error"; message: string }
  | { phase: "done"; report: AutofillReport; filename: string };

export function QuestionnaireAutofill({ token, verified }: QuestionnaireAutofillProps) {
  const [file, setFile] = useState<File | null>(null);
  const [state, setState] = useState<UploadState>({ phase: "idle" });
  const inputRef = useRef<HTMLInputElement>(null);

  async function runAutofill() {
    if (!file || !verified) return;
    setState({ phase: "running" });
    try {
      const result = await autofillQuestionnaire(token, file);
      const url = URL.createObjectURL(result.blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = result.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setState({ phase: "done", report: result.report, filename: result.filename });
    } catch (error) {
      setState({ phase: "error", message: error instanceof Error ? error.message : "Questionnaire autofill failed." });
    }
  }

  return (
    <div className="questionnaire">
      <div className="questionnaire__intro">
        <span className="questionnaire__eyebrow">CAIQ v4.1 + bespoke XLSX/CSV</span>
        <h3>Turn verified cloud evidence into review-ready answers.</h3>
        <p>
          Upload an XLSX or CSV. ZeroDock matches control IDs first, then cloud-security language, and returns the same file format with evidence links attached.
        </p>
        <div className="questionnaire__guardrail">
          Organizational claims stay with a person. When a question combines policy documentation with a technical control, ZeroDock fills only the verified technical portion and labels it partial. Failing controls are flagged as “would answer No” before submission.
        </div>
      </div>

      <div className="questionnaire__action">
        <input
          ref={inputRef}
          className="questionnaire__file-input"
          type="file"
          accept=".xlsx,.csv"
          disabled={!verified || state.phase === "running"}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setState({ phase: "idle" });
          }}
        />
        <button
          className="questionnaire__picker"
          type="button"
          disabled={!verified || state.phase === "running"}
          onClick={() => inputRef.current?.click()}
        >
          <span>{file ? file.name : "Choose questionnaire"}</span>
          <strong>XLSX / CSV</strong>
        </button>
        <button className="questionnaire__run" type="button" disabled={!file || !verified || state.phase === "running"} onClick={runAutofill}>
          {state.phase === "running" ? "Reviewing…" : "Autofill and download"}
        </button>
        {!verified && <p className="questionnaire__message questionnaire__message--warning">Autofill unlocks only after the browser verifies all six proof checks.</p>}
        {state.phase === "error" && <p className="questionnaire__message questionnaire__message--error">{state.message}</p>}
      </div>

      {state.phase === "done" && (
        <div className="questionnaire-report" aria-live="polite">
          <div><strong>{state.report.answered}</strong><span>answered</span></div>
          <div className="questionnaire-report__partial"><strong>{state.report.partial}</strong><span>partial</span></div>
          <div className="questionnaire-report__flag"><strong>{state.report.flagged}</strong><span>flagged</span></div>
          <div><strong>{state.report.needs_human}</strong><span>needs human</span></div>
          <div><strong>{state.report.hours_saved.toFixed(1)}h</strong><span>roughly saved</span></div>
          <p>Downloaded <b>{state.filename}</b>. Estimate: {state.report.estimate_basis}.</p>
        </div>
      )}
    </div>
  );
}

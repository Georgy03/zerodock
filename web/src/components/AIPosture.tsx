import type { ShareResponse } from "../verify/types";
import { deriveAIPosture } from "./deriveAIPosture";

export function AIPosture({ resp, verified }: { resp: ShareResponse; verified: boolean }) {
  const summary = deriveAIPosture(resp);
  return (
    <aside className={`ai-posture ai-posture--${summary.tone}`} aria-label="AI and machine learning posture">
      <div className="ai-posture__kicker">{verified ? "Hardware-attested AI posture" : "Unverified AI posture"}</div>
      <h3>{summary.heading}</h3>
      <p>{summary.resources}</p>
      <p className="ai-posture__caveat">{summary.logging}</p>
      <p className="ai-posture__inventory">{summary.agreements}</p>
      <small>Covers AI services in the scanned AWS accounts, not employee use of SaaS AI tools.</small>
    </aside>
  );
}

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
      <h4>What can AI execute?</h4>
      <p className="ai-posture__inventory">{summary.execute}</p>
      <h4>What data can AI retrieve?</h4>
      <p className="ai-posture__inventory">{summary.retrieve}</p>
      <h4>Can AI workloads reach external networks?</h4>
      <p className="ai-posture__inventory">{summary.egress}</p>
      <small>Covers AI services in the scanned AWS accounts, not employee use of SaaS AI tools.</small>
    </aside>
  );
}

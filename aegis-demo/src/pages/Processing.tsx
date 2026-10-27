import { LoaderCircle, ShieldCheck } from "lucide-react";

export default function Processing() {
  return (
    <div className="processing-page">
      <div className="processing-status" role="status" aria-live="polite">
        <LoaderCircle className="processing-spinner" size={34} aria-hidden="true" />
        <h1>Analyzing your repository</h1>
        <p>Security analysis is in progress. This may take a few minutes.</p>
      </div>
      <div className="ai-disclaimer">
        <ShieldCheck size={12} /> AI can make mistakes. Review findings before
        making changes.
      </div>
    </div>
  );
}

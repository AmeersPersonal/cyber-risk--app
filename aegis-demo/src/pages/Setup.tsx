import { ArrowRight, Github, Link2, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";

// ── Setup page ───────────────────────────────────────────────────────────────

interface Props {
  onStart: (repository: string, token: string) => Promise<void>;
  error?: string;
}

export default function Setup({ onStart, error: scanError }: Props) {
  const [url, setURL] = useState("");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const input = url.trim();
    if (!input) {
      setError("Enter a GitHub repository URL or owner/repository.");
      return;
    }

    let repository: string;
    try {
      const parsed = new URL(
        input.includes("://") ? input : `https://github.com/${input}`,
      );
      const parts = parsed.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (
        parsed.protocol !== "https:" ||
        parsed.hostname !== "github.com" ||
        parsed.username ||
        parsed.password ||
        parsed.port ||
        parsed.search ||
        parsed.hash ||
        parts.length !== 2
      ) {
        throw new Error("Invalid repository address");
      }
      const owner = parts[0];
      const name = parts[1].replace(/\.git$/i, "");
      if (
        !/^[A-Za-z0-9-]+$/.test(owner) ||
        !/^[A-Za-z0-9._-]+$/.test(name) ||
        name === "." ||
        name === ".."
      ) {
        throw new Error("Invalid repository name");
      }
      repository = `https://github.com/${owner}/${name}`;
    } catch {
      setError("Enter a valid github.com/owner/repository address.");
      return;
    }

    if (!token.trim()) {
      setError("Enter a GitHub access token to verify repository ownership.");
      return;
    }

    setError("");
    await onStart(repository, token.trim());
  }
  return (
    <div className="setup-page">
      <span className="large-brand">
        <ShieldCheck size={22} />
      </span>
      <h1>What are we securing today?</h1>
      <p className="intro">
        Give our AI agents a repository. Get a clear picture of its
        vulnerabilities, with verified findings and
        <br className="desktop-only" /> actionable fixes.
      </p>
      <form className="setup-form" onSubmit={submit}>
        <div className="field-label">
          <Github size={14} /> GitHub repository
        </div>
        <div className="repository-input">
          <Link2 size={16} />
          <input
            aria-label="GitHub repository or URL"
            autoComplete="url"
            required
            value={url}
            onChange={(e) => setURL(e.target.value)}
            placeholder="owner/repository"
          />
          <Github size={14} />
        </div>
        <label className="field-label" htmlFor="github-token">
          GitHub access token
        </label>
        <div className="repository-input token-input">
          <input
            id="github-token"
            aria-label="GitHub access token"
            type="password"
            autoComplete="off"
            required
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="Token with repository contents read access"
          />
        </div>
        <p className="helper">Used for this scan only. Ownership is verified by GitHub.</p>
        <div className="scan-use-reminder" role="note">
          Only scan repositories you own or have explicit permission to assess.
          Use a fine-grained, read-only token limited to this repository, and revoke it in GitHub after the scan or it may be potentially exposed.
          Avoid confidential code unless approved. Verify AI findings before acting.
          DEMO version currently and may/should be changed accordingly.
        </div>
        {(error || scanError) && (
          <div role="alert" className="error-message">
            {error || scanError}
          </div>
        )}
        <div className="flex flex-row items-center justify-center">
          <button className="primary-btn" type="submit">
            Start analysis <ArrowRight size={15} />
          </button>
        </div>
      </form>
      <div className="ai-disclaimer">
        AI can make mistakes. Review findings before making changes.
      </div>
    </div>
  );
}

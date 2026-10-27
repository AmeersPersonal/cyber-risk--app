import { Github, ShieldCheck } from "lucide-react";
import { useState, type SubmitEvent } from "react";
export default function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  function submit(e: SubmitEvent) {
    e.preventDefault();
    if (!email.includes("@") || password.length < 1) {
      setError("Enter an email and password to continue.");
      return;
    }
    onLogin();
  }
  return (
    <div className="login-screen">
      <div className="login-center">
        <span className="large-brand">
          <ShieldCheck size={22} />
        </span>
        <h1>Log In</h1>
        <p className="subtle">Demo workspace login</p>
        <form className="login-card" onSubmit={submit}>
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
            />
          </label>
          {error && <p className="error-message">{error}</p>}
          <button className="dark-btn" type="submit">
            Sign In
          </button>
          <button
            className="dark-btn github-login"
            type="button"
            onClick={onLogin}
          >
            <Github size={14} />
            GitHub demo login
          </button>
          <button
            type="button"
            className="forgot"
            onClick={() =>
              setError("Demo mode: any email and password will work.")
            }
          >
            Forgot password?
          </button>
        </form>
        <div className="login-fine">
          © 2026 Aegis Security
          <br />
          AI can make mistakes. Review findings before making changes.
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorNote } from "../components/ui";

export default function LoginPage() {
  const { login } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [status, setStatus] = useState<{ has_users: boolean; registration_open: boolean } | null>(
    null,
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ has_users: boolean; registration_open: boolean }>("/auth/status")
      .then((s) => {
        setStatus(s);
        if (!s.has_users) setMode("register");
      })
      .catch(() => setStatus(null));
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password, mode === "register");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  const firstRun = status && !status.has_users;

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="brand brand-lg">
          <svg viewBox="0 0 32 32" width="34" height="34" aria-hidden="true">
            <path
              d="M16 5 6 9v6c0 6.2 4.2 10.9 10 12.5 5.8-1.6 10-6.3 10-12.5V9L16 5Z"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.4"
              strokeLinejoin="round"
            />
            <circle cx="16" cy="15.5" r="3.2" fill="currentColor" />
          </svg>
          <span>Vigil</span>
        </div>
        <p className="muted">
          {firstRun
            ? "First run — create the administrator account."
            : mode === "login"
              ? "Sign in to the security console."
              : "Create an analyst account."}
        </p>
        <label>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            minLength={3}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
            required
            minLength={8}
          />
        </label>
        <ErrorNote error={error} />
        <button className="btn btn-primary" disabled={busy}>
          {busy ? "…" : mode === "login" ? "Sign in" : "Create account"}
        </button>
        {status?.has_users && status.registration_open && (
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
          >
            {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
          </button>
        )}
      </form>
    </div>
  );
}

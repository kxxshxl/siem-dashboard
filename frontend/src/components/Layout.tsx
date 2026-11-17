import { useCallback } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { useData } from "../hooks";
import { useLive, useLiveRefresh } from "../live";
import type { Page, Alert } from "../types";
import { SeverityBadge } from "./ui";

const NAV = [
  { to: "/", label: "Overview", icon: "◧" },
  { to: "/alerts", label: "Alerts", icon: "⚑" },
  { to: "/events", label: "Events", icon: "≡" },
  { to: "/rules", label: "Detection rules", icon: "⛬" },
  { to: "/simulator", label: "Attack simulator", icon: "⚔" },
  { to: "/ingest", label: "Ingest logs", icon: "⇪" },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const { connected, eventsPerSecond, toasts, dismissToast } = useLive();
  const openAlerts = useData(
    () => api<Page<Alert>>("/alerts", { query: { status: "open", page_size: 1 } }),
    [],
  );
  const refreshCount = useCallback(() => void openAlerts.reload(), [openAlerts.reload]);
  useLiveRefresh(["alert", "alert_updated", "purged"], refreshCount, 500);

  return (
    <div className="shell">
      <aside className="sidebar">
        <Link to="/" className="brand">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
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
        </Link>
        <nav>
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className="nav-link">
              <span className="nav-icon" aria-hidden="true">
                {n.icon}
              </span>
              <span>{n.label}</span>
              {n.to === "/alerts" && (openAlerts.data?.total ?? 0) > 0 && (
                <span className="nav-count">{openAlerts.data?.total}</span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className={`live ${connected ? "on" : ""}`}>
            <span className="dot" />
            {connected ? `Live · ${eventsPerSecond.toFixed(1)} ev/s` : "Reconnecting…"}
          </div>
          <div className="whoami">
            <span>
              {user?.username} <span className="muted">· {user?.role}</span>
            </span>
            <button className="btn btn-ghost btn-sm" onClick={logout}>
              Sign out
            </button>
          </div>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
      <div className="toasts" aria-live="polite">
        {toasts.map(({ id, alert }) => (
          <div key={id} className={`toast toast-${alert.severity}`}>
            <div className="toast-head">
              <SeverityBadge severity={alert.severity} />
              <button className="btn-x" aria-label="Dismiss" onClick={() => dismissToast(id)}>
                ×
              </button>
            </div>
            <Link to={`/alerts/${alert.id}`} onClick={() => dismissToast(id)}>
              <strong>{alert.title}</strong>
            </Link>
            <div className="muted small">{alert.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

import type { ReactNode } from "react";
import { attackUrl, label } from "../format";
import type { AlertStatus, Severity } from "../types";

const SEV_ICON: Record<Severity, string> = {
  critical: "▲",
  high: "◆",
  medium: "●",
  low: "▼",
  info: "○",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = severity as Severity;
  return (
    <span className={`sev sev-${s}`}>
      <span aria-hidden="true">{SEV_ICON[s] ?? "•"}</span>
      {label(s)}
    </span>
  );
}

export function StatusBadge({ status }: { status: AlertStatus | string }) {
  return <span className={`status status-${status}`}>{label(status)}</span>;
}

export function Technique({ id, tactic }: { id: string | null; tactic?: string | null }) {
  if (!id) return <span className="muted">—</span>;
  return (
    <a className="technique" href={attackUrl(id)} target="_blank" rel="noreferrer" title={tactic ?? id}>
      {id}
    </a>
  );
}

export function StatCard({
  label: title,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "critical" | "serious" | "good";
}) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-label">{title}</div>
      <div className="stat-value">{value}</div>
      {hint !== undefined && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Pagination({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="pagination">
      <span className="muted">
        {from}–{to} of {total.toLocaleString()}
      </span>
      <button className="btn btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        ← Prev
      </button>
      <span>
        {page} / {pages}
      </span>
      <button className="btn btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Next →
      </button>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="error-note" role="alert">
      {error}
    </div>
  );
}

export function Json({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

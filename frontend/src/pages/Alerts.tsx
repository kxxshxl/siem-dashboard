import { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Empty, ErrorNote, Pagination, Panel, SeverityBadge, StatusBadge, Technique } from "../components/ui";
import { label, num, timeAgo } from "../format";
import { useData } from "../hooks";
import { useLiveRefresh } from "../live";
import type { Alert, AlertStatus, Page } from "../types";

const STATUSES: AlertStatus[] = ["open", "in_progress", "resolved", "dismissed"];
const SEVERITIES = ["critical", "high", "medium", "low"];

export default function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const status = params.get("status") ?? "open,in_progress";
  const severity = params.get("severity") ?? "";
  const tactic = params.get("tactic") ?? "";
  const q = params.get("q") ?? "";
  const page = Number(params.get("page") ?? 1);
  const [search, setSearch] = useState(q);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkError, setBulkError] = useState<string | null>(null);

  const { data, error, reload } = useData(
    () => api<Page<Alert>>("/alerts", { query: { status, severity, tactic, q, page, page_size: 25 } }),
    [status, severity, tactic, q, page],
  );
  useLiveRefresh(["alert", "alert_updated", "purged"], reload);

  function update(next: Record<string, string>) {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(next)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    if (!("page" in next)) p.delete("page");
    setParams(p);
    setSelected(new Set());
  }

  const activeStatuses = new Set(status.split(",").filter(Boolean));
  function toggleStatus(s: AlertStatus) {
    const next = new Set(activeStatuses);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    update({ status: [...next].join(",") || STATUSES.join(",") });
  }

  async function bulk(to: AlertStatus) {
    setBulkError(null);
    try {
      await api("/alerts/bulk", { method: "POST", body: { ids: [...selected], status: to } });
      setSelected(new Set());
      void reload();
    } catch (e) {
      setBulkError(e instanceof Error ? e.message : String(e));
    }
  }

  const items = data?.items ?? [];
  const allChecked = items.length > 0 && items.every((a) => selected.has(a.id));

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">Correlated detections, de-duplicated per rule and entity.</p>
        </div>
      </header>

      <div className="filters">
        <div className="chips" role="group" aria-label="Status">
          {STATUSES.map((s) => (
            <button key={s} className={`chip ${activeStatuses.has(s) ? "active" : ""}`} onClick={() => toggleStatus(s)}>
              {label(s)}
            </button>
          ))}
        </div>
        <select value={severity} onChange={(e) => update({ severity: e.target.value })} aria-label="Severity">
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {label(s)}
            </option>
          ))}
          <option value="critical,high">Critical + high</option>
        </select>
        {tactic && (
          <button className="chip active" onClick={() => update({ tactic: "" })} title="Clear tactic filter">
            Tactic: {tactic} ×
          </button>
        )}
        <form
          className="search"
          onSubmit={(e) => {
            e.preventDefault();
            update({ q: search });
          }}
        >
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title, entity, technique…" />
        </form>
      </div>

      {selected.size > 0 && (
        <div className="bulkbar">
          <span>{selected.size} selected</span>
          <button className="btn btn-sm" onClick={() => bulk("in_progress")}>Investigate</button>
          <button className="btn btn-sm" onClick={() => bulk("resolved")}>Resolve</button>
          <button className="btn btn-sm" onClick={() => bulk("dismissed")}>Dismiss as false positive</button>
          <button className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
        </div>
      )}
      <ErrorNote error={error ?? bulkError} />

      <Panel>
        {data && items.length === 0 ? (
          <Empty>
            No alerts match. Launch a scenario from the <Link to="/simulator">attack simulator</Link>.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table clickable">
              <thead>
                <tr>
                  <th className="check">
                    <input
                      type="checkbox"
                      aria-label="Select all"
                      checked={allChecked}
                      onChange={() => setSelected(allChecked ? new Set() : new Set(items.map((a) => a.id)))}
                    />
                  </th>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Entity</th>
                  <th>ATT&amp;CK</th>
                  <th className="num">Hits</th>
                  <th className="num">Events</th>
                  <th>Last seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <tr key={a.id} onClick={() => navigate(`/alerts/${a.id}`)}>
                    <td className="check" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select alert ${a.id}`}
                        checked={selected.has(a.id)}
                        onChange={() => {
                          const next = new Set(selected);
                          if (next.has(a.id)) next.delete(a.id);
                          else next.add(a.id);
                          setSelected(next);
                        }}
                      />
                    </td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>
                      <div className="strong">{a.title}</div>
                      <div className="muted small ellipsis">{a.summary}</div>
                    </td>
                    <td className="mono small">{a.entity || "—"}</td>
                    <td onClick={(e) => e.stopPropagation()}><Technique id={a.mitre_technique} tactic={a.mitre_tactic} /></td>
                    <td className="num">{num(a.hit_count)}</td>
                    <td className="num">{num(a.event_count)}</td>
                    <td className="nowrap" title={a.last_seen}>{timeAgo(a.last_seen)}</td>
                    <td>
                      <StatusBadge status={a.status} />
                      {a.assignee && <div className="muted small">@{a.assignee}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data && data.total > 0 && (
          <Pagination page={page} pageSize={25} total={data.total} onPage={(p) => update({ page: String(p) })} />
        )}
      </Panel>
    </div>
  );
}

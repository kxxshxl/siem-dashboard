import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { MitreMatrix, RankedBars, SEVERITY_COLOR, VolumeChart } from "../components/charts";
import { Empty, ErrorNote, Panel, SeverityBadge, StatCard, StatusBadge } from "../components/ui";
import { compact, label, num, timeAgo } from "../format";
import { useData, useInterval } from "../hooks";
import { useLiveRefresh } from "../live";
import type { Overview, Severity } from "../types";

const RANGES = [
  { hours: 1, label: "1h" },
  { hours: 6, label: "6h" },
  { hours: 24, label: "24h" },
  { hours: 168, label: "7d" },
];

export default function OverviewPage() {
  const [hours, setHours] = useState(24);
  const navigate = useNavigate();
  const { data, error, reload } = useData(
    () => api<Overview>("/stats/overview", { query: { hours } }),
    [hours],
  );
  useLiveRefresh(["alert", "alert_updated", "purged"], reload, 1000);
  useInterval(reload, 15000);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Security overview</h1>
          <p className="muted">Event volume, detections and adversary behaviour across the estate.</p>
        </div>
        <div className="segmented" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button key={r.hours} className={hours === r.hours ? "active" : ""} onClick={() => setHours(r.hours)}>
              {r.label}
            </button>
          ))}
        </div>
      </header>
      <ErrorNote error={error} />
      {!data ? (
        <div className="skeleton" />
      ) : (
        <>
          <div className="stats">
            <StatCard label={`Events · ${RANGES.find((r) => r.hours === hours)?.label}`} value={compact(data.totals.events)} hint={`${num(data.totals.events_all_time)} stored`} />
            <StatCard label="Ingest rate" value={`${data.totals.events_per_minute}/min`} hint="last 5 minutes" />
            <StatCard label="Open alerts" value={num(data.totals.open_alerts)} hint={`${num(data.totals.alerts)} raised in range`} />
            <StatCard
              label="Open critical / high"
              value={
                <>
                  {num(data.totals.open_critical)}
                  <span className="muted"> / </span>
                  {num(data.totals.open_high)}
                </>
              }
              hint={data.totals.open_critical > 0 ? "▲ needs triage" : "✓ none critical"}
              tone={data.totals.open_critical > 0 ? "critical" : data.totals.open_high > 0 ? "serious" : "good"}
            />
            <StatCard label="Active rules" value={data.engine.rules_enabled} hint={`${num(data.engine.tracked_entities)} entities tracked`} />
          </div>

          <div className="grid grid-2-1">
            <Panel title="Event volume">
              <VolumeChart data={data.timeline} field="events" kind="area" noun="events" hours={hours} bucketSeconds={data.range.bucket_seconds} />
              <h3 className="sub">Detections (by first seen)</h3>
              <VolumeChart data={data.timeline} field="alerts" kind="bar" noun="alerts" hours={hours} bucketSeconds={data.range.bucket_seconds} />
            </Panel>
            <Panel title="Alerts by severity">
              {data.totals.alerts === 0 ? (
                <Empty>No alerts in this range. Try the attack simulator.</Empty>
              ) : (
                <RankedBars
                  data={[...data.alerts_by_severity].reverse().map((d) => ({ ...d, name: label(d.name) }))}
                  noun="alerts"
                  colorFor={(n) => SEVERITY_COLOR[n.toLowerCase() as Severity]}
                />
              )}
              <h3 className="sub">Status</h3>
              <div className="status-row">
                {(["open", "in_progress", "resolved", "dismissed"] as const).map((s) => (
                  <Link key={s} to={`/alerts?status=${s}`} className="status-cell">
                    <StatusBadge status={s} />
                    <strong>{num(data.alerts_by_status[s] ?? 0)}</strong>
                  </Link>
                ))}
              </div>
            </Panel>
          </div>

          <Panel title="MITRE ATT&CK coverage" actions={<span className="muted small">alerts per technique · click a tactic to filter</span>}>
            {data.mitre.length === 0 ? (
              <Empty>No mapped detections yet.</Empty>
            ) : (
              <MitreMatrix data={data.mitre} onSelect={(t) => navigate(`/alerts?tactic=${encodeURIComponent(t)}`)} />
            )}
          </Panel>

          <div className="grid grid-3">
            <Panel title="Recent alerts" actions={<Link to="/alerts">View all →</Link>}>
              {data.recent_alerts.length === 0 ? (
                <Empty>Quiet so far.</Empty>
              ) : (
                <ul className="alert-list">
                  {data.recent_alerts.map((a) => (
                    <li key={a.id}>
                      <Link to={`/alerts/${a.id}`}>
                        <SeverityBadge severity={a.severity} />
                        <span className="alert-list-title">{a.title}</span>
                        <span className="muted small">
                          {a.entity} · {timeAgo(a.last_seen)}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
            <Panel title="Top source IPs">
              <table className="table compact">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th className="num">Events</th>
                  </tr>
                </thead>
                <tbody>
                  {data.top_sources.map((s) => (
                    <tr key={s.ip}>
                      <td>
                        <Link to={`/events?src_ip=${encodeURIComponent(s.ip)}`} className="mono">
                          {s.ip}
                        </Link>
                        {s.flagged && <span className="flag" title="Involved in an alert">▲ alerted</span>}
                      </td>
                      <td className="num">{num(s.events)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
            <Panel title="Events by category">
              <RankedBars data={data.events_by_category} noun="events" />
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}

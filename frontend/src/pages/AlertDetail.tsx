import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import EventTable from "../components/EventTable";
import { ErrorNote, Json, Panel, SeverityBadge, StatusBadge, Technique } from "../components/ui";
import { dateTime, num, timeAgo } from "../format";
import { useData } from "../hooks";
import { useLiveRefresh } from "../live";
import type { AlertDetail, AlertStatus } from "../types";

const ACTIONS: Record<AlertStatus, { to: AlertStatus; label: string; primary?: boolean }[]> = {
  open: [
    { to: "in_progress", label: "Start investigation", primary: true },
    { to: "dismissed", label: "Dismiss (false positive)" },
  ],
  in_progress: [
    { to: "resolved", label: "Resolve", primary: true },
    { to: "dismissed", label: "Dismiss (false positive)" },
  ],
  resolved: [{ to: "open", label: "Reopen" }],
  dismissed: [{ to: "open", label: "Reopen" }],
};

export default function AlertDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data, error, reload, setData } = useData(() => api<AlertDetail>(`/alerts/${id}`), [id]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  useLiveRefresh(["alert_updated"], reload, 1500);

  async function patch(body: Record<string, unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      setData(await api<AlertDetail>(`/alerts/${id}`, { method: "PATCH", body }));
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (error) return <div className="page"><ErrorNote error={error} /></div>;
  if (!data) return <div className="page"><div className="skeleton" /></div>;

  const durationSec = (new Date(data.last_seen).getTime() - new Date(data.first_seen).getTime()) / 1000;

  return (
    <div className="page">
      <Link to="/alerts" className="back">← Alerts</Link>
      <header className="page-head">
        <div>
          <div className="row gap">
            <SeverityBadge severity={data.severity} />
            <StatusBadge status={data.status} />
            <span className="muted">#{data.id}</span>
          </div>
          <h1>{data.title}</h1>
          <p>{data.summary}</p>
        </div>
        <div className="row gap wrap">
          {ACTIONS[data.status].map((a) => (
            <button
              key={a.to}
              className={`btn ${a.primary ? "btn-primary" : ""}`}
              disabled={busy}
              onClick={() => patch({ status: a.to })}
            >
              {a.label}
            </button>
          ))}
          {data.assignee !== user?.username && (
            <button className="btn btn-ghost" disabled={busy} onClick={() => patch({ assignee: user?.username })}>
              Assign to me
            </button>
          )}
        </div>
      </header>
      <ErrorNote error={actionError} />

      <div className="grid grid-2-1">
        <div className="stack">
          <Panel title="Context">
            <dl className="facts">
              <dt>Entity</dt>
              <dd className="mono">{data.entity || "—"}</dd>
              <dt>MITRE ATT&amp;CK</dt>
              <dd>
                {data.mitre_tactic ?? "—"} · <Technique id={data.mitre_technique} />
              </dd>
              <dt>First seen</dt>
              <dd>{dateTime(data.first_seen)}</dd>
              <dt>Last seen</dt>
              <dd>
                {dateTime(data.last_seen)} <span className="muted">({timeAgo(data.last_seen)})</span>
              </dd>
              <dt>Activity span</dt>
              <dd>{durationSec < 120 ? `${Math.round(durationSec)}s` : `${Math.round(durationSec / 60)} min`}</dd>
              <dt>Detections merged</dt>
              <dd>{num(data.hit_count)}</dd>
              <dt>Assignee</dt>
              <dd>{data.assignee ? `@${data.assignee}` : <span className="muted">unassigned</span>}</dd>
            </dl>
          </Panel>
          <Panel title={`Evidence · ${data.events.length} events`}>
            <EventTable events={data.events} compact />
          </Panel>
        </div>
        <div className="stack">
          <Panel title="Activity">
            <form
              className="note-form"
              onSubmit={(e) => {
                e.preventDefault();
                if (!note.trim()) return;
                void patch({ note }).then(() => setNote(""));
              }}
            >
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Add an investigation note…"
                rows={3}
              />
              <button className="btn btn-sm" disabled={busy || !note.trim()}>Add note</button>
            </form>
            <ol className="timeline">
              {[...data.notes].reverse().map((n) => (
                <li key={n.id}>
                  <div className="small">
                    <strong>@{n.author}</strong> <span className="muted">· {timeAgo(n.created_at)}</span>
                  </div>
                  <div>{n.body}</div>
                </li>
              ))}
              <li>
                <div className="small muted">{dateTime(data.created_at)}</div>
                <div>Alert raised by detection engine</div>
              </li>
            </ol>
          </Panel>
          {data.rule && (
            <Panel title="Detection rule" actions={<Link to={`/rules?open=${data.rule.id}`}>Open →</Link>}>
              <p className="small">{data.rule.description}</p>
              <p className="small muted">
                kind: <span className="mono">{data.rule.kind}</span>
              </p>
              <Json value={data.rule.definition} />
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

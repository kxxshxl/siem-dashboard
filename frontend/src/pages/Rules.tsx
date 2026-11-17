import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Empty, ErrorNote, Json, Panel, SeverityBadge, Technique } from "../components/ui";
import { num } from "../format";
import { useData } from "../hooks";
import type { Rule, RuleKind, Severity } from "../types";

const TEMPLATES: Record<RuleKind, object> = {
  match: {
    where: { category: "process", "process.cmdline": { contains: "mimikatz" } },
    group_by: ["host"],
    summary: "Credential dumping tool on {host} by {username}",
  },
  threshold: {
    where: { category: "web", "http.status": { gte: 500 } },
    group_by: ["src_ip"],
    count: 20,
    window_seconds: 60,
    summary: "{count} server errors triggered by {src_ip}",
  },
  cardinality: {
    where: { category: "dns", action: "dns_query" },
    group_by: ["host"],
    field: "dns.query",
    distinct: 50,
    window_seconds: 60,
    summary: "{host} resolved {count} distinct domains in {seconds}s",
  },
  sequence: {
    group_by: ["username"],
    window_seconds: 900,
    steps: [
      { name: "login", where: { action: "login_success" } },
      { name: "priv", where: { action: "sudo", "process.cmdline": { contains: "/etc/shadow" } } },
    ],
    summary: "{username} read /etc/shadow shortly after logging in",
  },
};

interface Draft {
  id?: number;
  slug: string;
  name: string;
  description: string;
  kind: RuleKind;
  severity: Severity;
  mitre_tactic: string;
  mitre_technique: string;
  definition: string;
}

interface BacktestResult {
  events_scanned: number;
  detections: { entity: string; summary: string; event_count: number; last_seen: string }[];
}

const blank = (kind: RuleKind = "threshold"): Draft => ({
  slug: "",
  name: "",
  description: "",
  kind,
  severity: "medium",
  mitre_tactic: "",
  mitre_technique: "",
  definition: JSON.stringify(TEMPLATES[kind], null, 2),
});

export default function RulesPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [params, setParams] = useSearchParams();
  const openId = Number(params.get("open") ?? 0);
  const { data: rules, error, reload, setData } = useData(() => api<Rule[]>("/rules"), []);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [backtest, setBacktest] = useState<BacktestResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (openId) document.getElementById(`rule-${openId}`)?.scrollIntoView({ block: "center" });
  }, [openId, rules]);

  async function toggle(rule: Rule) {
    const updated = await api<Rule>(`/rules/${rule.id}`, { method: "PATCH", body: { enabled: !rule.enabled } });
    setData((rules ?? []).map((r) => (r.id === rule.id ? updated : r)));
  }

  function edit(rule: Rule) {
    setDraft({
      id: rule.id,
      slug: rule.slug,
      name: rule.name,
      description: rule.description,
      kind: rule.kind,
      severity: rule.severity,
      mitre_tactic: rule.mitre_tactic ?? "",
      mitre_technique: rule.mitre_technique ?? "",
      definition: JSON.stringify(rule.definition, null, 2),
    });
    setBacktest(null);
    setEditorError(null);
  }

  function parsed(): Record<string, unknown> | null {
    try {
      return JSON.parse(draft!.definition);
    } catch (e) {
      setEditorError(`Definition is not valid JSON: ${(e as Error).message}`);
      return null;
    }
  }

  async function runBacktest() {
    const definition = parsed();
    if (!definition) return;
    setBusy(true);
    setEditorError(null);
    try {
      setBacktest(
        await api<BacktestResult>("/rules/test", {
          method: "POST",
          body: { kind: draft!.kind, definition, lookback_minutes: 60 * 24 },
        }),
      );
    } catch (e) {
      setEditorError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    const definition = parsed();
    if (!definition || !draft) return;
    setBusy(true);
    setEditorError(null);
    const body = {
      name: draft.name,
      description: draft.description,
      severity: draft.severity,
      mitre_tactic: draft.mitre_tactic || null,
      mitre_technique: draft.mitre_technique || null,
      definition,
    };
    try {
      if (draft.id) await api(`/rules/${draft.id}`, { method: "PATCH", body });
      else await api("/rules", { method: "POST", body: { ...body, slug: draft.slug, kind: draft.kind } });
      setDraft(null);
      void reload();
    } catch (e) {
      setEditorError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(rule: Rule) {
    if (!confirm(`Delete rule "${rule.name}"? Existing alerts are kept.`)) return;
    await api(`/rules/${rule.id}`, { method: "DELETE" });
    setDraft(null);
    void reload();
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Detection rules</h1>
          <p className="muted">
            Streaming correlation rules — <code>match</code>, <code>threshold</code>, <code>cardinality</code> and{" "}
            <code>sequence</code> — evaluated on every ingested event.
          </p>
        </div>
        {isAdmin && (
          <button className="btn btn-primary" onClick={() => { setDraft(blank()); setBacktest(null); setEditorError(null); }}>
            + New rule
          </button>
        )}
      </header>
      <ErrorNote error={error} />

      {draft && (
        <Panel title={draft.id ? `Edit · ${draft.name}` : "New rule"} className="editor" actions={<button className="btn-x" onClick={() => setDraft(null)} aria-label="Close">×</button>}>
          <div className="form-grid">
            {!draft.id && (
              <label>
                Slug
                <input value={draft.slug} onChange={(e) => setDraft({ ...draft, slug: e.target.value })} placeholder="dns-burst" />
              </label>
            )}
            <label className="span-2">
              Name
              <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </label>
            <label>
              Kind
              <select
                value={draft.kind}
                disabled={!!draft.id}
                onChange={(e) => {
                  const kind = e.target.value as RuleKind;
                  setDraft({ ...draft, kind, definition: JSON.stringify(TEMPLATES[kind], null, 2) });
                }}
              >
                {Object.keys(TEMPLATES).map((k) => (
                  <option key={k}>{k}</option>
                ))}
              </select>
            </label>
            <label>
              Severity
              <select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value as Severity })}>
                {["low", "medium", "high", "critical"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </label>
            <label>
              MITRE tactic
              <input value={draft.mitre_tactic} onChange={(e) => setDraft({ ...draft, mitre_tactic: e.target.value })} placeholder="Discovery" />
            </label>
            <label>
              Technique
              <input value={draft.mitre_technique} onChange={(e) => setDraft({ ...draft, mitre_technique: e.target.value })} placeholder="T1046" />
            </label>
            <label className="span-full">
              Description
              <input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
            </label>
            <label className="span-full">
              Definition (JSON)
              <textarea className="code" rows={14} spellCheck={false} value={draft.definition} onChange={(e) => setDraft({ ...draft, definition: e.target.value })} />
            </label>
          </div>
          <p className="muted small">
            Operators: <code>eq ne in not_in contains not_contains startswith endswith regex gt gte lt lte exists cidr not_cidr</code>. Use{" "}
            <code>any: [...]</code> for OR, dotted paths like <code>http.status</code> for nested fields, and{" "}
            <code>{"{field}"}</code>/<code>{"{count}"}</code> placeholders in <code>summary</code>.
          </p>
          <ErrorNote error={editorError} />
          <div className="row gap">
            <button className="btn" onClick={runBacktest} disabled={busy}>Backtest on last 24h</button>
            <button className="btn btn-primary" onClick={save} disabled={busy}>{draft.id ? "Save changes" : "Create rule"}</button>
          </div>
          {backtest && (
            <div className="backtest">
              <strong>
                {backtest.detections.length} detection{backtest.detections.length === 1 ? "" : "s"}
              </strong>{" "}
              <span className="muted">across {num(backtest.events_scanned)} events</span>
              <ul>
                {backtest.detections.slice(-10).reverse().map((d, i) => (
                  <li key={i}>
                    <span className="mono small">{d.entity}</span> — {d.summary}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>
      )}

      <Panel>
        {rules && rules.length === 0 ? (
          <Empty>No rules.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>On</th>
                  <th>Rule</th>
                  <th>Kind</th>
                  <th>Severity</th>
                  <th>ATT&amp;CK</th>
                  <th className="num">Alerts</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(rules ?? []).map((r) => (
                  <RuleRow
                    key={r.id}
                    rule={r}
                    expanded={openId === r.id}
                    onExpand={() => setParams(openId === r.id ? {} : { open: String(r.id) })}
                    onToggle={isAdmin ? () => void toggle(r) : undefined}
                    onEdit={isAdmin ? () => edit(r) : undefined}
                    onDelete={isAdmin && !r.builtin ? () => void remove(r) : undefined}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function RuleRow({
  rule,
  expanded,
  onExpand,
  onToggle,
  onEdit,
  onDelete,
}: {
  rule: Rule;
  expanded: boolean;
  onExpand: () => void;
  onToggle?: () => void;
  onEdit?: () => void;
  onDelete?: () => void;
}) {
  return (
    <>
      <tr id={`rule-${rule.id}`} className={`${rule.enabled ? "" : "disabled"} ${expanded ? "expanded" : ""}`}>
        <td>
          <label className="switch" title={onToggle ? "Enable / disable" : "Admins only"}>
            <input type="checkbox" checked={rule.enabled} disabled={!onToggle} onChange={onToggle} aria-label={`Enable ${rule.name}`} />
            <span />
          </label>
        </td>
        <td>
          <button className="linklike strong" onClick={onExpand}>{rule.name}</button>
          <div className="muted small">
            {rule.slug} {rule.builtin ? "· built-in" : "· custom"}
          </div>
        </td>
        <td><span className="kind">{rule.kind}</span></td>
        <td><SeverityBadge severity={rule.severity} /></td>
        <td>
          <Technique id={rule.mitre_technique} tactic={rule.mitre_tactic} />
          <div className="muted small">{rule.mitre_tactic}</div>
        </td>
        <td className="num">
          {rule.alert_count > 0 ? <Link to={`/alerts?status=open,in_progress,resolved,dismissed&q=${encodeURIComponent(rule.name)}`}>{num(rule.alert_count)}</Link> : 0}
        </td>
        <td className="nowrap">
          {onEdit && <button className="btn btn-ghost btn-sm" onClick={onEdit}>Edit</button>}
          {onDelete && <button className="btn btn-ghost btn-sm danger" onClick={onDelete}>Delete</button>}
        </td>
      </tr>
      {expanded && (
        <tr className="detail-row">
          <td colSpan={7}>
            <p>{rule.description}</p>
            <Json value={rule.definition} />
          </td>
        </tr>
      )}
    </>
  );
}

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { ErrorNote, Panel, Technique } from "../components/ui";
import { num } from "../format";
import { useData } from "../hooks";
import type { IngestResult, Scenario, SimHost, SimulationResult } from "../types";

export default function SimulatorPage() {
  const { user } = useAuth();
  const catalog = useData(() => api<{ scenarios: Scenario[]; hosts: SimHost[] }>("/simulator/scenarios"), []);
  const noise = useData(() => api<{ enabled: boolean; events_per_second: number }>("/simulator/noise"), []);
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [attacker, setAttacker] = useState("");
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, SimulationResult>>({});
  const [rate, setRate] = useState(2);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const serverRate = noise.data?.events_per_second;
  useEffect(() => {
    if (serverRate) setRate(serverRate);
  }, [serverRate]);

  async function launch(s: Scenario) {
    setRunning(s.slug);
    setError(null);
    try {
      const result = await api<SimulationResult>("/simulator/run", {
        method: "POST",
        body: { scenario: s.slug, target_host: targets[s.slug] || null, attacker_ip: attacker || null },
      });
      setResults((r) => ({ ...r, [s.slug]: result }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(null);
    }
  }

  async function setNoise(enabled: boolean) {
    noise.setData(await api("/simulator/noise", { method: "POST", body: { enabled, events_per_second: rate } }));
  }

  async function backfill() {
    setRunning("backfill");
    setMessage(null);
    try {
      const r = await api<IngestResult>("/simulator/backfill", { method: "POST", body: { hours: 24 } });
      setMessage(`Backfilled ${num(r.accepted)} events and raised ${r.alerts_created} alerts across the last 24 hours.`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(null);
    }
  }

  async function purge() {
    if (!confirm("Delete ALL events and alerts? Rules and users are kept.")) return;
    await api("/simulator/data", { method: "DELETE" });
    setResults({});
    setMessage("All events and alerts deleted.");
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Attack simulator</h1>
          <p className="muted">
            Replays realistic multi-stage intrusions into the pipeline so you can watch detections fire end to end. Attackers use
            RFC&nbsp;5737 documentation addresses.
          </p>
        </div>
      </header>
      <ErrorNote error={error} />
      {message && <div className="info-note">{message}</div>}

      <div className="grid grid-2-1">
        <Panel title="Background traffic">
          <p className="small muted">
            Benign web, DNS, firewall, process and login activity — the haystack your detections need to stay quiet on.
          </p>
          <div className="row gap wrap">
            <label className="toggle">
              <input type="checkbox" checked={!!noise.data?.enabled} onChange={(e) => void setNoise(e.target.checked)} />
              {noise.data?.enabled ? `Generating ${noise.data.events_per_second} ev/s` : "Off"}
            </label>
            <label className="row gap small">
              Rate
              <input type="range" min={0.5} max={20} step={0.5} value={rate} onChange={(e) => setRate(Number(e.target.value))}
                onPointerUp={() => noise.data?.enabled && void setNoise(true)} />
              <span className="mono">{rate} ev/s</span>
            </label>
          </div>
        </Panel>
        <Panel title="History">
          <div className="row gap wrap">
            <button className="btn" onClick={backfill} disabled={running !== null}>
              {running === "backfill" ? "Backfilling…" : "Backfill 24h of history"}
            </button>
            {user?.role === "admin" && (
              <button className="btn btn-ghost danger" onClick={purge}>
                Purge all data
              </button>
            )}
          </div>
        </Panel>
      </div>

      <div className="row gap wrap">
        <label className="row gap small">
          Attacker IP
          <input value={attacker} onChange={(e) => setAttacker(e.target.value)} placeholder="random 203.0.113.x" className="mono" />
        </label>
      </div>

      <div className="scenarios">
        {catalog.data?.scenarios.map((s) => {
          const result = results[s.slug];
          return (
            <Panel key={s.slug} className="scenario">
              <h2>{s.name}</h2>
              <p className="small">{s.description}</p>
              <div className="chips">
                {s.techniques.map((t) => (
                  <Technique key={t} id={t} />
                ))}
              </div>
              <div className="muted small">{s.tactics.join(" → ")}</div>
              <div className="row gap scenario-actions">
                <select
                  value={targets[s.slug] ?? s.default_target}
                  onChange={(e) => setTargets({ ...targets, [s.slug]: e.target.value })}
                  aria-label="Target host"
                >
                  {catalog.data?.hosts.map((h) => (
                    <option key={h.name} value={h.name}>
                      {h.name} ({h.role})
                    </option>
                  ))}
                </select>
                <button className="btn btn-primary" onClick={() => launch(s)} disabled={running !== null}>
                  {running === s.slug ? "Running…" : "Launch"}
                </button>
              </div>
              {result && (
                <div className="sim-result">
                  <strong>{num(result.accepted)}</strong> events from <span className="mono">{result.attacker_ip}</span> →{" "}
                  {result.target_host}:{" "}
                  {result.alerts_created + result.alerts_updated > 0 ? (
                    <Link to="/alerts">
                      {result.alerts_created} new / {result.alerts_updated} updated alerts →
                    </Link>
                  ) : (
                    <span className="muted">no alerts (are the rules enabled?)</span>
                  )}
                </div>
              )}
              <div className="muted small">Expected: {s.expected_rules.join(", ")}</div>
            </Panel>
          );
        })}
      </div>
    </div>
  );
}

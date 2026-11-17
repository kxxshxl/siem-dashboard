import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ErrorNote, Panel, SeverityBadge } from "../components/ui";
import type { IngestResult, Severity } from "../types";

const SAMPLE = `Nov 18 09:12:44 web-01 sshd[2211]: Failed password for invalid user oracle from 198.51.100.23 port 51122 ssh2
Nov 18 09:12:47 web-01 sshd[2213]: Accepted publickey for deploy from 10.0.5.21 port 50514 ssh2
Nov 18 09:13:02 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart app
Nov 18 09:13:10 gw-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.80 DST=10.0.1.10 LEN=44 PROTO=TCP SPT=40112 DPT=3389 WINDOW=1024 SYN
203.0.113.80 - - [18/Nov/2026:09:13:15 +0000] "GET /products.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 312 "-" "sqlmap/1.8"
src=10.0.2.20 dst=192.0.2.44 dpt=443 action=connection_allowed category=network bytes_out=88000000 host=db-01
{"category": "process", "action": "process_start", "host": "wks-alice", "username": "alice", "process": {"cmdline": "powershell.exe -nop -enc SQBFAFgA"}}`;

interface Preview {
  parsers: Record<string, number>;
  errors: { line: number; error: string }[];
  events: {
    timestamp: string | null;
    source: string;
    category: string;
    action: string;
    severity: Severity;
    host: string | null;
    username: string | null;
    src_ip: string | null;
    message: string;
  }[];
}

export default function IngestPage() {
  const [text, setText] = useState("");
  const [host, setHost] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [result, setResult] = useState<IngestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(path: "/events/parse" | "/events/raw") {
    setBusy(true);
    setError(null);
    try {
      const body = { text, host: host || null };
      if (path === "/events/parse") {
        setPreview(await api<Preview>(path, { method: "POST", body }));
        setResult(null);
      } else {
        setResult(await api<IngestResult>(path, { method: "POST", body }));
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Ingest logs</h1>
          <p className="muted">
            Paste raw lines — syslog / auth.log, UFW / iptables, nginx &amp; Apache access logs, <code>key=value</code> or JSON — and
            they are parsed, normalised and run through detection.
          </p>
        </div>
      </header>

      <div className="grid grid-2-1">
        <Panel title="Raw input" actions={<button className="btn btn-ghost btn-sm" onClick={() => setText(SAMPLE)}>Load sample</button>}>
          <textarea className="code" rows={14} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} placeholder="One log line per row…" />
          <div className="row gap wrap">
            <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="Default host (optional)" />
            <button className="btn" disabled={busy || !text.trim()} onClick={() => run("/events/parse")}>Preview parse</button>
            <button className="btn btn-primary" disabled={busy || !text.trim()} onClick={() => run("/events/raw")}>Ingest</button>
          </div>
          <ErrorNote error={error} />
          {result && (
            <div className="info-note">
              Ingested {result.accepted} events ({Object.entries(result.parsers).map(([k, v]) => `${v} ${k}`).join(", ")}).{" "}
              {result.alerts_created + result.alerts_updated > 0 ? (
                <Link to="/alerts">{result.alerts_created} new alerts, {result.alerts_updated} updated →</Link>
              ) : (
                "No detections."
              )}
            </div>
          )}
        </Panel>
        <Panel title="Ship logs via API">
          <p className="small muted">Structured JSON, authenticated with a user token or <code>X-Ingest-Token</code>:</p>
          <pre className="json">{`curl -X POST http://localhost:8080/api/events \\
  -H "X-Ingest-Token: $VIGIL_INGEST_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '[{"source":"app","category":"authentication",
        "action":"login_failure","src_ip":"198.51.100.9",
        "username":"bob","host":"api-01"}]'`}</pre>
          <p className="small muted">Or tail a file with the bundled shipper:</p>
          <pre className="json">{`python tools/ship_logs.py /var/log/auth.log \\
  --url http://localhost:8080 --follow`}</pre>
        </Panel>
      </div>

      {preview && (
        <Panel title={`Preview · ${preview.events.length} events`} actions={<span className="muted small">{Object.entries(preview.parsers).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span>}>
          <div className="table-wrap">
            <table className="table compact">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Category</th>
                  <th>Action</th>
                  <th>Host</th>
                  <th>User</th>
                  <th>Src IP</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {preview.events.map((e, i) => (
                  <tr key={i}>
                    <td><SeverityBadge severity={e.severity} /></td>
                    <td>{e.source}</td>
                    <td>{e.category}</td>
                    <td className="mono small">{e.action}</td>
                    <td>{e.host ?? "—"}</td>
                    <td>{e.username ?? "—"}</td>
                    <td className="mono small">{e.src_ip ?? "—"}</td>
                    <td className="small ellipsis msg">{e.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {preview.errors.length > 0 && <ErrorNote error={preview.errors.map((e) => `line ${e.line}: ${e.error}`).join("; ")} />}
        </Panel>
      )}
    </div>
  );
}

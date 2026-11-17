import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import EventTable from "../components/EventTable";
import { ErrorNote, Pagination, Panel } from "../components/ui";
import { label, num } from "../format";
import { useData } from "../hooks";
import { useLiveRefresh } from "../live";
import type { Page, SiemEvent } from "../types";

const FILTER_KEYS = ["category", "source", "host", "action", "severity", "src_ip", "username"] as const;
const PAGE_SIZE = 50;

export default function EventsPage() {
  const [params, setParams] = useSearchParams();
  const page = Number(params.get("page") ?? 1);
  const q = params.get("q") ?? "";
  const [search, setSearch] = useState(q);
  const [tail, setTail] = useState(true);

  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""]));
  const filterKey = FILTER_KEYS.map((k) => filters[k]).join("|");

  const facets = useData(() => api<Record<string, string[]>>("/events/facets"), []);
  const { data, error, reload } = useData(
    () => api<Page<SiemEvent>>("/events", { query: { ...filters, q, page, page_size: PAGE_SIZE } }),
    [filterKey, q, page],
  );
  useLiveRefresh(["ingest", "purged"], () => tail && page === 1 && void reload(), 1500);

  function update(next: Record<string, string>) {
    const p = new URLSearchParams(params);
    for (const [k, v] of Object.entries(next)) {
      if (v) p.set(k, v);
      else p.delete(k);
    }
    if (!("page" in next)) p.delete("page");
    setParams(p);
  }

  const active = FILTER_KEYS.filter((k) => filters[k]);

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Event explorer</h1>
          <p className="muted">
            {data ? `${num(data.total)} matching events` : "Search normalised telemetry"} · click a value to pivot
          </p>
        </div>
        <label className="toggle">
          <input type="checkbox" checked={tail} onChange={(e) => setTail(e.target.checked)} />
          Live tail
        </label>
      </header>

      <div className="filters">
        <form
          className="search grow"
          onSubmit={(e) => {
            e.preventDefault();
            update({ q: search });
          }}
        >
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search message, host, user, IP…" />
        </form>
        {(["category", "source", "host"] as const).map((k) => (
          <select key={k} value={filters[k]} onChange={(e) => update({ [k]: e.target.value })} aria-label={k}>
            <option value="">All {k === "category" ? "categories" : `${k}s`}</option>
            {(facets.data?.[k] ?? []).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        ))}
        <select value={filters.severity} onChange={(e) => update({ severity: e.target.value })} aria-label="severity">
          <option value="">Any severity</option>
          <option value="medium,high,critical">Medium and above</option>
          <option value="low,medium,high,critical">Low and above</option>
        </select>
      </div>

      {(active.length > 0 || q) && (
        <div className="chips">
          {active.map((k) => (
            <button key={k} className="chip active" onClick={() => update({ [k]: "" })}>
              {label(k)}: {filters[k]} ×
            </button>
          ))}
          {q && (
            <button className="chip active" onClick={() => { setSearch(""); update({ q: "" }); }}>
              “{q}” ×
            </button>
          )}
          <button className="chip" onClick={() => { setSearch(""); setParams(new URLSearchParams()); }}>
            Clear all
          </button>
        </div>
      )}
      <ErrorNote error={error} />

      <Panel>
        {data ? (
          <>
            <EventTable events={data.items} onPivot={(f, v) => update({ [f]: v })} />
            <Pagination page={page} pageSize={PAGE_SIZE} total={data.total} onPage={(p) => update({ page: String(p) })} />
          </>
        ) : (
          <div className="skeleton" />
        )}
      </Panel>
    </div>
  );
}

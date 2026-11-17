import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { clock, compact, num, TACTIC_ORDER } from "../format";
import type { NamedCount, Overview, Severity } from "../types";

const AXIS = { stroke: "var(--axis)", fontSize: 11, tickLine: false } as const;

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--status-critical)",
  high: "var(--status-serious)",
  medium: "var(--status-warning)",
  low: "var(--series-1)",
  info: "var(--text-muted)",
};

interface TipProps {
  active?: boolean;
  label?: string | number;
  payload?: { value: number; payload: Record<string, unknown> }[];
  noun: string;
  fmtLabel?: (l: string) => string;
}

function ChartTip({ active, payload, label, noun, fmtLabel }: TipProps) {
  if (!active || !payload?.length) return null;
  const text = fmtLabel ? fmtLabel(String(label)) : String(label);
  return (
    <div className="chart-tip">
      <div className="chart-tip-label">{text}</div>
      <div className="chart-tip-value">
        {num(payload[0].value)} <span className="muted">{noun}</span>
      </div>
    </div>
  );
}

function tickFormatter(hours: number) {
  return (iso: string) =>
    hours > 24
      ? new Date(iso).toLocaleDateString(undefined, { weekday: "short", hour: "2-digit" })
      : clock(iso);
}

function bucketLabel(bucketSeconds: number) {
  return (iso: string) => {
    const start = new Date(iso);
    const end = new Date(start.getTime() + bucketSeconds * 1000);
    return `${start.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })} – ${end.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
  };
}

export function VolumeChart({
  data,
  field,
  hours,
  bucketSeconds,
  noun,
  kind,
}: {
  data: Overview["timeline"];
  field: "events" | "alerts";
  hours: number;
  bucketSeconds: number;
  noun: string;
  kind: "area" | "bar";
}) {
  const common = {
    data,
    margin: { top: 8, right: 8, bottom: 0, left: -12 },
  };
  const xAxis = (
    <XAxis dataKey="t" {...AXIS} tickFormatter={tickFormatter(hours)} minTickGap={48} axisLine={{ stroke: "var(--baseline)" }} />
  );
  const yAxis = <YAxis {...AXIS} axisLine={false} tickFormatter={compact} allowDecimals={false} width={48} />;
  const grid = <CartesianGrid vertical={false} stroke="var(--grid)" />;
  const tip = (
    <Tooltip
      cursor={kind === "area" ? { stroke: "var(--axis)", strokeWidth: 1 } : { fill: "var(--hover-wash)" }}
      content={<ChartTip noun={noun} fmtLabel={bucketLabel(bucketSeconds)} />}
      isAnimationActive={false}
    />
  );
  return (
    <ResponsiveContainer width="100%" height={kind === "area" ? 220 : 150}>
      {kind === "area" ? (
        <AreaChart {...common}>
          <defs>
            <linearGradient id="vol-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--series-1)" stopOpacity={0.28} />
              <stop offset="100%" stopColor="var(--series-1)" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          {grid}
          {xAxis}
          {yAxis}
          {tip}
          <Area
            type="monotone"
            dataKey={field}
            stroke="var(--series-1)"
            strokeWidth={2}
            fill="url(#vol-fill)"
            activeDot={{ r: 4, stroke: "var(--surface-1)", strokeWidth: 2 }}
            isAnimationActive={false}
          />
        </AreaChart>
      ) : (
        <BarChart {...common} barCategoryGap={2}>
          {grid}
          {xAxis}
          {yAxis}
          {tip}
          <Bar dataKey={field} fill="var(--series-1)" radius={[4, 4, 0, 0]} maxBarSize={18} isAnimationActive={false} />
        </BarChart>
      )}
    </ResponsiveContainer>
  );
}

export function RankedBars({
  data,
  noun,
  colorFor,
  height,
}: {
  data: NamedCount[];
  noun: string;
  colorFor?: (name: string) => string;
  height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height ?? Math.max(120, data.length * 32 + 16)}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 48, bottom: 4, left: 8 }} barCategoryGap={8}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="name" {...AXIS} axisLine={false} width={104} tick={{ fill: "var(--text-secondary)", fontSize: 12 }} />
        <Tooltip
          cursor={{ fill: "var(--hover-wash)" }}
          content={<ChartTip noun={noun} />}
          isAnimationActive={false}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18} isAnimationActive={false} minPointSize={2}>
          {data.map((d) => (
            <Cell key={d.name} fill={colorFor ? colorFor(d.name) : "var(--series-1)"} />
          ))}
          <LabelList dataKey="count" position="right" formatter={(v: unknown) => num(Number(v))} fill="var(--text-secondary)" fontSize={12} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** ATT&CK-style matrix: tactics as columns (kill-chain order), techniques as cells. */
export function MitreMatrix({
  data,
  onSelect,
}: {
  data: Overview["mitre"];
  onSelect?: (tactic: string) => void;
}) {
  const max = Math.max(1, ...data.map((d) => d.count));
  const byTactic = new Map<string, { technique: string; count: number }[]>();
  for (const d of data) {
    const list = byTactic.get(d.tactic) ?? [];
    list.push({ technique: d.technique, count: d.count });
    byTactic.set(d.tactic, list);
  }
  const tactics = TACTIC_ORDER.filter((t) => byTactic.has(t)).concat(
    [...byTactic.keys()].filter((t) => !TACTIC_ORDER.includes(t)),
  );
  // sequential blue ramp, lightest step kept visible against the surface
  const steps = ["var(--seq-250)", "var(--seq-350)", "var(--seq-450)", "var(--seq-550)", "var(--seq-650)"];
  return (
    <div className="matrix" role="table" aria-label="Alerts by MITRE ATT&CK tactic and technique">
      {tactics.map((tactic) => (
        <div className="matrix-col" role="rowgroup" key={tactic}>
          <button className="matrix-head" onClick={() => onSelect?.(tactic)} title={`Show ${tactic} alerts`}>
            {tactic}
          </button>
          {byTactic.get(tactic)!.map((cell) => {
            const step = Math.min(steps.length - 1, Math.floor((cell.count / max) * steps.length));
            return (
              <a
                key={cell.technique}
                role="row"
                className={`matrix-cell ${step >= 2 ? "on-dark" : ""}`}
                style={{ background: steps[step] }}
                href={`https://attack.mitre.org/techniques/${cell.technique.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
                title={`${cell.technique}: ${cell.count} alert${cell.count === 1 ? "" : "s"}`}
              >
                <span>{cell.technique}</span>
                <strong>{cell.count}</strong>
              </a>
            );
          })}
        </div>
      ))}
    </div>
  );
}

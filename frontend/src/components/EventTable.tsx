import { Fragment, useState } from "react";
import { dateTime } from "../format";
import type { SiemEvent } from "../types";
import { Empty, Json, SeverityBadge } from "./ui";

export default function EventTable({
  events,
  compact = false,
  onPivot,
}: {
  events: SiemEvent[];
  compact?: boolean;
  onPivot?: (field: string, value: string) => void;
}) {
  const [open, setOpen] = useState<number | null>(null);
  if (events.length === 0) return <Empty>No events.</Empty>;

  const pivot = (field: string, value: string | null) =>
    value && onPivot ? (
      <button className="pivot" onClick={(e) => { e.stopPropagation(); onPivot(field, value); }} title={`Filter by ${field}`}>
        {value}
      </button>
    ) : (
      value ?? <span className="muted">—</span>
    );

  return (
    <div className="table-wrap">
      <table className={`table clickable ${compact ? "compact" : ""}`}>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Source</th>
            <th>Action</th>
            <th>Host</th>
            {!compact && <th>User</th>}
            <th>Src → Dst</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <Fragment key={e.id}>
              <tr onClick={() => setOpen(open === e.id ? null : e.id)} className={open === e.id ? "expanded" : ""}>
                <td className="nowrap mono small">{dateTime(e.timestamp)}</td>
                <td><SeverityBadge severity={e.severity} /></td>
                <td className="small">{pivot("source", e.source)}</td>
                <td className="small mono">{pivot("action", e.action)}</td>
                <td className="small nowrap">{pivot("host", e.host)}</td>
                {!compact && <td className="small">{pivot("username", e.username)}</td>}
                <td className="mono small nowrap">
                  {pivot("src_ip", e.src_ip)}
                  {e.dst_ip && (
                    <>
                      {" → "}
                      {e.dst_ip}
                      {e.dst_port != null && `:${e.dst_port}`}
                    </>
                  )}
                </td>
                <td className="small ellipsis msg">{e.message}</td>
              </tr>
              {open === e.id && (
                <tr className="detail-row">
                  <td colSpan={compact ? 7 : 8}>
                    <Json value={{ ...e, raw: undefined }} />
                    {e.raw && (
                      <>
                        <div className="muted small">Raw</div>
                        <pre className="json">{e.raw}</pre>
                      </>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}

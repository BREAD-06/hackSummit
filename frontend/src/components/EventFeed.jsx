import React from "react";

import { Card, Chip, bytes, clockTime, count } from "./ui.jsx";

const TYPES = [
  ["all", "All"],
  ["file", "File"],
  ["usb", "USB"],
  ["logon", "Logon"],
];

/** `detail` arrives as a JSON *string* from SQLite; parse defensively. */
function detailOf(event) {
  if (!event.detail) return {};
  if (typeof event.detail === "object") return event.detail;
  try {
    return JSON.parse(event.detail);
  } catch {
    return { raw: String(event.detail) };
  }
}

/**
 * The raw signal, unaggregated.
 *
 * The threat queue shows conclusions; this shows what they were drawn from. It is
 * the fastest way to tell "the model is quiet because nothing is happening" apart
 * from "the model is quiet because the collector stopped" — and to confirm on sight
 * that only metadata crosses the wire: a path, a size, an extension, never content.
 */
export default function EventFeed({ events }) {
  const [type, setType] = React.useState("all");
  const all = events || [];
  const rows = type === "all" ? all : all.filter((e) => e.log_type === type);

  return (
    <Card
      title="Endpoint activity"
      hint={`${count(all.length)} most recent`}
      actions={
        <div className="tabs" role="tablist" aria-label="Filter by signal type">
          {TYPES.map(([key, label]) => (
            <button
              key={key}
              className="tab"
              role="tab"
              aria-selected={type === key}
              onClick={() => setType(key)}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      {rows.length === 0 ? (
        <p className="empty-state">
          {all.length === 0
            ? "No events received yet."
            : `No ${type} events in the recent window.`}
        </p>
      ) : (
        <div className="table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Signal</th>
                <th>Action</th>
                <th>User</th>
                <th>Target</th>
                <th className="num">Size</th>
                <th>Flags</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => {
                const d = detailOf(e);
                return (
                  <tr key={e.id}>
                    <td className="nowrap mono dim">{clockTime(e.ts)}</td>
                    <td className="nowrap">{e.log_type}</td>
                    <td className="nowrap mono">{e.action}</td>
                    <td className="nowrap">{e.user || "—"}</td>
                    <td className="truncate mono" title={e.path || ""}>
                      {e.path || d.drive || d.terminal || "—"}
                    </td>
                    <td className="num mono">{e.size_bytes ? bytes(e.size_bytes) : "—"}</td>
                    <td>
                      <div className="evidence">
                        {d.sensitive && <Chip>sensitive</Chip>}
                        {d.removable && <Chip>removable</Chip>}
                        {d.writes_coalesced > 1 && (
                          <Chip title="Repeated writes to one file within the flush interval, collapsed into a single event">
                            ×{d.writes_coalesced}
                          </Chip>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

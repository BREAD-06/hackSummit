import React from "react";

import { Card, Chip, SeverityChip, bytes, clockTime, count, humanRule } from "./ui.jsx";

const STATUS_FILTERS = [
  { key: "all", label: "All" },
  { key: "open", label: "Open" },
  { key: "blocked", label: "Blocked" },
  { key: "dismissed", label: "Dismissed" },
];

/**
 * The live threat queue, and the only place an analyst writes to the system.
 *
 * Block/Dismiss is both the incident disposition and the reward signal for the
 * Q-learning policy, so the buttons carry real weight. They sit in the last
 * column and must never be the thing that scrolls out of view — that is why the
 * detail rail collapses below the queue under 1400px rather than squeezing it.
 *
 * The evidence column exists so a verdict does not require opening the detail
 * panel first: fired rules and the file volume that triggered the window are the
 * two things that decide most calls.
 */
export default function ThreatTable({
  threats,
  selectedId,
  onSelect,
  onVerdict,
  pending,
  statusFilter,
  onStatusFilter,
  severityFilter,
  onSeverityFilter,
}) {
  const rows = threats || [];

  return (
    <Card
      title="Threat queue"
      hint={`${count(rows.length)} shown`}
      actions={
        <div className="filters">
          <div className="tabs" role="tablist" aria-label="Filter by status">
            {STATUS_FILTERS.map((f) => (
              <button
                key={f.key}
                className="tab"
                role="tab"
                aria-selected={statusFilter === f.key}
                onClick={() => onStatusFilter(f.key)}
              >
                {f.label}
              </button>
            ))}
          </div>
          <label className="select-wrap">
            <span className="sr-only">Filter by severity</span>
            <select value={severityFilter} onChange={(e) => onSeverityFilter(e.target.value)}>
              <option value="all">Any severity</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High and above</option>
              <option value="MEDIUM">Medium and above</option>
            </select>
          </label>
        </div>
      }
    >
      {rows.length === 0 ? (
        <p className="empty-state">
          No threats match this filter. The queue fills as endpoints stream activity.
        </p>
      ) : (
        <div className="table-wrap" style={{ maxHeight: 430, overflowY: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Response</th>
                <th>Detected</th>
                <th>User / host</th>
                <th>Evidence</th>
                <th className="num">Score</th>
                <th className="verdict-col">Verdict</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((t) => {
                const open = t.status === "open";
                const busy = pending === t.id;
                const f = t.features || {};
                return (
                  <tr
                    key={t.id}
                    className={`clickable ${selectedId === t.id ? "selected" : ""}`}
                    onClick={() => onSelect(t.id)}
                  >
                    <td>
                      <SeverityChip severity={t.severity} />
                    </td>
                    <td className="nowrap mono">{t.action}</td>
                    <td className="nowrap mono dim">{clockTime(t.created_at)}</td>
                    <td className="truncate-sm">
                      {t.user}
                      <span className="dim"> @ {t.host}</span>
                    </td>
                    <td className="evidence-cell">
                      <div className="evidence">
                        {(t.rules_fired || []).length > 0 ? (
                          (t.rules_fired || []).map((r) => (
                            <Chip key={r}>{humanRule(r)}</Chip>
                          ))
                        ) : (
                          <span className="dim">model only</span>
                        )}
                      </div>
                      <div className="dim sub-line">
                        {count(f.file_count || 0)} files · {bytes(f.file_bytes_total || 0)}
                        {f.usb_connect ? ` · ${f.usb_connect} USB` : ""}
                        {f.is_after_hours ? " · after hours" : ""}
                      </div>
                    </td>
                    <td className="num mono">{Number(t.anomaly_score).toFixed(3)}</td>
                    <td className="verdict-col">
                      {/* Status lives here rather than in its own column: once a
                          verdict exists it replaces the buttons, which says
                          "already decided" more plainly than two gray buttons. */}
                      {open ? (
                        <div className="verdicts" onClick={(e) => e.stopPropagation()}>
                          <button
                            className="verdict block"
                            disabled={busy}
                            title="Confirm the threat: contain, and teach the policy to block this state"
                            onClick={() => onVerdict(t.id, "block")}
                          >
                            Block
                          </button>
                          <button
                            className="verdict dismiss"
                            disabled={busy}
                            title="False positive: close it, and teach the policy to stand down here"
                            onClick={() => onVerdict(t.id, "dismiss")}
                          >
                            Dismiss
                          </button>
                        </div>
                      ) : (
                        <span className="dim decided">{t.status}</span>
                      )}
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

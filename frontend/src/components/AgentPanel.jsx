import React from "react";

import { Card, ago, count, dateTime } from "./ui.jsx";

/**
 * Endpoint health, and the one admin action the dashboard owns.
 *
 * "Online" here means a live PQC session exists — not merely that the endpoint
 * enrolled once. That distinction is the whole point of the panel: an agent that
 * enrolled last week and has been dead since is the failure mode a quiet threat
 * queue hides, so `last seen` sits next to the status dot rather than a tab away.
 *
 * Minting an enrollment token is a privileged action, so the token is shown once,
 * inline, with what to do with it — never mailed anywhere by this UI.
 */
export default function AgentPanel({ agents, onEnrollToken }) {
  const rows = agents || [];
  const [token, setToken] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const online = rows.filter((a) => a.online).length;

  const mint = async () => {
    setBusy(true);
    try {
      setToken(await onEnrollToken());
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title="Endpoints"
      hint={rows.length ? `${online} of ${rows.length} online` : null}
      actions={
        <button className="verdict" disabled={busy} onClick={mint}>
          {busy ? "Minting…" : "Enroll new endpoint"}
        </button>
      }
    >
      {token && (
        <div className="banner learned">
          <div>
            <strong>One-time enrollment token</strong>
            <div className="mono" style={{ margin: "4px 0", overflowWrap: "anywhere" }}>
              {token.token}
            </div>
            <span className="dim">
              Put this in <span className="mono">agent_config.yaml</span> as{" "}
              <span className="mono">enroll_token</span> on the new endpoint. It works once.
            </span>
          </div>
          <button onClick={() => setToken(null)} aria-label="Dismiss token">
            ×
          </button>
        </div>
      )}

      {rows.length === 0 ? (
        <p className="empty-state">
          No endpoints enrolled yet. Mint a token above, then run the agent on the machine you want
          to monitor.
        </p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Host</th>
                <th>Last seen</th>
                <th className="num">Batches</th>
                <th className="num">Events</th>
                <th className="num">Seq</th>
                <th>Session</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => {
                const s = a.session;
                return (
                  <tr key={a.agent_id}>
                    <td className="nowrap">
                      <span
                        className={`dot ${a.online ? "live" : "offline"}`}
                        style={{ display: "inline-block", marginRight: 8 }}
                        aria-hidden="true"
                      />
                      <span className="mono">{a.agent_id}</span>
                    </td>
                    <td className="nowrap">{a.host || "—"}</td>
                    <td className="nowrap" title={dateTime(a.last_seen)}>
                      {ago(a.last_seen)}
                    </td>
                    <td className="num">{s ? count(s.batches) : "—"}</td>
                    <td className="num">{s ? count(s.events) : "—"}</td>
                    <td className="num">{s ? count(s.last_seq) : "—"}</td>
                    <td className="nowrap dim">
                      {s
                        ? `${s.key_bits}-bit, since ${dateTime(s.established_at)}`
                        : `enrolled ${dateTime(a.enrolled_at)} — no live session`}
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

import React from "react";

import { Card, Chip, SeverityChip, bytes, count, dateTime, humanRule } from "./ui.jsx";

/**
 * Everything behind one decision.
 *
 * A verdict here is a training label, not just a ticket disposition, so the panel
 * has to show *why* the system landed where it did: the discretized RL state, the
 * policy's current Q-values for that state, the rules that fired, and the raw
 * window features. "Policy now" can differ from the action that was taken —
 * that gap is the learning made visible, so it is labelled rather than hidden.
 */

// Features worth naming, in the order an analyst reads them. Anything else in the
// record still renders below under "other" — nothing is silently dropped.
const PRIMARY = [
  ["file_count", "Files touched", (v) => count(v)],
  ["file_bytes_total", "Bytes written", (v) => bytes(v)],
  ["max_file_bytes", "Largest file", (v) => bytes(v)],
  ["distinct_dirs", "Distinct folders", (v) => count(v)],
  ["sensitive_count", "Sensitive paths", (v) => count(v)],
  ["removable_write_count", "Writes to removable", (v) => count(v)],
  ["delete_count", "Deletions", (v) => count(v)],
  ["usb_connect", "USB connects", (v) => count(v)],
  ["usb_disconnect", "USB disconnects", (v) => count(v)],
  ["logon_count", "Logons", (v) => count(v)],
  ["logoff_count", "Logoffs", (v) => count(v)],
];

const DERIVED = new Set(["risk", "confidence", "explored", "hour", "day_of_week", "is_after_hours"]);

function stateParts(state) {
  // "ah1|usb0|vol2|anom1" — the four axes of the 32-state space.
  const vol = ["none", "low", "medium", "high"];
  const m = /^ah([01])\|usb([01])\|vol([0-3])\|anom([01])$/.exec(state || "");
  if (!m) return null;
  return [
    ["After hours", m[1] === "1" ? "yes" : "no"],
    ["USB present", m[2] === "1" ? "yes" : "no"],
    ["File volume", vol[Number(m[3])]],
    ["Model flagged", m[4] === "1" ? "anomalous" : "normal"],
  ];
}

export default function ThreatDetail({ threat, loading }) {
  if (loading && !threat) {
    return (
      <Card title="Threat detail">
        <p className="empty-state">Loading…</p>
      </Card>
    );
  }
  if (!threat) {
    return (
      <Card title="Threat detail">
        <p className="empty-state">Select a row to see the evidence behind a decision.</p>
      </Card>
    );
  }

  const f = threat.features || {};
  const policy = threat.policy;
  const parts = stateParts(threat.state);
  const drifted = policy && policy.action !== threat.action;

  const shown = new Set([...PRIMARY.map(([k]) => k), ...DERIVED]);
  const other = Object.entries(f).filter(([k, v]) => !shown.has(k) && Number(v) !== 0);

  return (
    <Card
      title={`Threat #${threat.id}`}
      hint={dateTime(threat.created_at)}
      actions={<SeverityChip severity={threat.severity} />}
      className="detail"
    >
      <dl>
        <dt>Response</dt>
        <dd>
          <span className="mono">{threat.action}</span>
          {threat.features?.explored ? <span className="dim"> (exploratory)</span> : null}
        </dd>
        <dt>Status</dt>
        <dd>{threat.status}</dd>
        <dt>Identity</dt>
        <dd>
          {threat.user} @ {threat.host}
        </dd>
        <dt>Endpoint</dt>
        <dd className="mono">{threat.agent_id}</dd>
        <dt>Window</dt>
        <dd>
          {dateTime(threat.window_start)} · hour {threat.hour}
        </dd>
        <dt>Anomaly score</dt>
        <dd>
          {Number(threat.anomaly_score).toFixed(4)}{" "}
          <span className="dim">{threat.is_anomaly ? "below threshold" : "within normal range"}</span>
        </dd>
        {f.risk !== undefined && (
          <>
            <dt>Rule risk</dt>
            <dd>{Number(f.risk).toFixed(2)}</dd>
          </>
        )}
        {f.confidence !== undefined && (
          <>
            <dt>Policy confidence</dt>
            <dd>{(Number(f.confidence) * 100).toFixed(0)}%</dd>
          </>
        )}
      </dl>

      <h3>Rules fired</h3>
      {(threat.rules_fired || []).length ? (
        <div className="evidence">
          {threat.rules_fired.map((r) => (
            <Chip key={r}>{humanRule(r)}</Chip>
          ))}
        </div>
      ) : (
        <p className="dim" style={{ margin: 0 }}>
          None — this window was flagged by the model alone.
        </p>
      )}

      <h3>Decision state</h3>
      <p className="mono dim" style={{ margin: "0 0 8px" }}>
        {threat.state || "—"}
      </p>
      {parts && (
        <dl>
          {parts.map(([k, v]) => (
            <React.Fragment key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </React.Fragment>
          ))}
        </dl>
      )}

      {policy && (
        <>
          <h3>Policy for this state, now</h3>
          <table className="qmini">
            <tbody>
              {Object.entries(policy.q_values).map(([action, value]) => (
                <tr key={action} className={action === policy.action ? "best" : ""}>
                  <td className="mono">{action}</td>
                  <td className="num qval">{Number(value).toFixed(3)}</td>
                  <td className="dim">{action === policy.action ? "← would choose" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {drifted && (
            <p className="dim" style={{ margin: "8px 0 0" }}>
              The policy has since learned to <strong>{policy.action}</strong> here; this threat was
              handled as {threat.action}.
            </p>
          )}
        </>
      )}

      <h3>Window features</h3>
      <dl>
        {PRIMARY.filter(([k]) => f[k] !== undefined).map(([k, label, fmt]) => (
          <React.Fragment key={k}>
            <dt>{label}</dt>
            <dd>{fmt(f[k])}</dd>
          </React.Fragment>
        ))}
        {other.map(([k, v]) => (
          <React.Fragment key={k}>
            <dt>{humanRule(k)}</dt>
            <dd>{Number(v).toLocaleString("en-US")}</dd>
          </React.Fragment>
        ))}
      </dl>
    </Card>
  );
}

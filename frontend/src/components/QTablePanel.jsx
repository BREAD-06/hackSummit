import React from "react";

import { Card, count } from "./ui.jsx";

const ACTIONS = ["DISMISS", "ALERT", "BLOCK"];

/**
 * The learned policy: 32 states × 3 actions.
 *
 * Diverging bars, not a heatmap. A Q-value has *polarity* — positive means the
 * analyst pool has endorsed that response in that state, negative means they have
 * rejected it — and polarity wants two hues around a neutral zero, not a
 * single-hue magnitude ramp that would make "strongly wrong" and "strongly right"
 * look like the same intensity. Length also reads more precisely than color, and
 * at 32 rows there is room for it.
 *
 * The categorical blue/red pair carries the sign; the number is printed beside
 * every bar, so nothing here depends on distinguishing the two colors. The status
 * palette is deliberately *not* reused — a red Q-bar is a negative value, not a
 * critical severity.
 */
export default function QTablePanel({ table, stats, highlightState, onReset }) {
  const rows = table || [];
  const [view, setView] = React.useState("trained");
  const [resetting, setResetting] = React.useState(false);

  const scale = React.useMemo(() => {
    let peak = 1;
    for (const r of rows) {
      for (const a of ACTIONS) peak = Math.max(peak, Math.abs(Number(r.q?.[a]) || 0));
    }
    return peak;
  }, [rows]);

  const visible = React.useMemo(() => {
    if (view === "all") return rows;
    // "Trained" means a verdict has actually touched the state; the rest are still
    // sitting on the rule-based prior and say nothing about analyst intent.
    const trained = rows.filter((r) => !r.untrained);
    return trained.length ? trained : rows;
  }, [rows, view]);

  const onlyPrior = view === "trained" && visible.length === rows.length && rows.length > 0
    && rows.every((r) => r.untrained);

  const doReset = async () => {
    if (!window.confirm(
      "Discard every learned Q-value and fall back to the rule-based prior?\n\n"
      + "Analyst feedback collected so far will no longer influence decisions.",
    )) return;
    setResetting(true);
    try {
      await onReset();
    } finally {
      setResetting(false);
    }
  };

  return (
    <Card
      title="Learned policy (Q-table)"
      hint={
        stats
          ? `${stats.n_states_trained}/${stats.n_states} states trained · α ${stats.alpha} · γ ${stats.gamma}`
          : null
      }
      actions={
        <div className="filters">
          <div className="tabs" role="tablist" aria-label="Q-table rows">
            {[
              ["trained", "Trained"],
              ["all", "All 32"],
            ].map(([key, label]) => (
              <button
                key={key}
                className="tab"
                role="tab"
                aria-selected={view === key}
                onClick={() => setView(key)}
              >
                {label}
              </button>
            ))}
          </div>
          <button className="verdict" disabled={resetting} onClick={doReset}>
            {resetting ? "Resetting…" : "Reset policy"}
          </button>
        </div>
      }
    >
      {onlyPrior && (
        <p className="dim" style={{ margin: "0 0 10px", fontSize: 12 }}>
          No verdicts yet — every row below is still the rule-based cold-start prior.
        </p>
      )}

      <div className="table-wrap" style={{ maxHeight: 380, overflowY: "auto" }}>
        <table>
          <thead>
            <tr>
              <th>State</th>
              {ACTIONS.map((a) => (
                <th key={a} colSpan={2}>
                  {a}
                </th>
              ))}
              <th>Chooses</th>
              <th className="num">Verdicts</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => (
              <tr
                key={r.state}
                className={`${r.state === highlightState ? "selected" : ""} ${
                  r.untrained ? "stale" : ""
                }`}
              >
                <td className="mono nowrap" title={describe(r)}>
                  {r.state}
                </td>
                {ACTIONS.map((a) => {
                  const v = Number(r.q?.[a]) || 0;
                  const pct = (Math.abs(v) / scale) * 50;
                  return (
                    <React.Fragment key={a}>
                      <td className="qcell">
                        <div className="qbar">
                          <i
                            className={v >= 0 ? "pos" : "neg"}
                            style={{ width: `${pct}%` }}
                            aria-hidden="true"
                          />
                        </div>
                      </td>
                      <td className="num qval nowrap">{v.toFixed(2)}</td>
                    </React.Fragment>
                  );
                })}
                <td className="nowrap mono">{r.best_action}</td>
                <td className="num">{count(r.total_visits || 0)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="legend">
        <span>
          <i style={{ background: "var(--series-1)" }} /> endorsed (Q &gt; 0)
        </span>
        <span>
          <i style={{ background: "var(--series-neg)" }} /> rejected (Q &lt; 0)
        </span>
        <span className="dim">dimmed rows are untouched by feedback — still the rule prior</span>
      </div>
    </Card>
  );
}

function describe(r) {
  return [
    r.after_hours ? "after hours" : "business hours",
    r.usb ? "USB present" : "no USB",
    `${r.volume} file volume`,
    r.ml_anomaly ? "model flagged anomalous" : "model says normal",
    `rule risk ${r.risk_prior}`,
  ].join(" · ");
}

import React from "react";

import { SEVERITIES, count } from "./ui.jsx";

/**
 * The top row: one hero number and four supporting tiles.
 *
 * Open threats is the hero because it is the only number that implies an action.
 * The rest exist to answer "is the system actually running" — an empty dashboard
 * because nothing happened and an empty dashboard because the agent died look
 * identical unless ingest and endpoint counts are on screen.
 *
 * No chart here: these are single values, and a bar of length one is not a chart.
 */
function Tile({ label, value, sub, hero = false, children }) {
  return (
    <div className={`tile ${hero ? "hero" : ""}`}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
      {children}
    </div>
  );
}

export default function KpiRow({ summary, agents, rl }) {
  const s = summary || {};
  const sev = s.by_severity || {};
  const stat = s.by_status || {};

  const online = (agents || []).filter((a) => a.online).length;
  const serious = (Number(sev.HIGH) || 0) + (Number(sev.CRITICAL) || 0);

  return (
    <div className="kpis">
      <Tile
        hero
        label="Open threats"
        value={count(s.open_threats ?? 0)}
        sub={`${count(s.total_threats ?? 0)} total · ${count(stat.blocked ?? 0)} blocked · ${count(
          stat.dismissed ?? 0,
        )} dismissed`}
      >
        <div className="chips">
          {SEVERITIES.map((name) => (
            <span key={name} className={`chip sev-${name}`}>
              <i className="swatch" aria-hidden="true" />
              {name} {Number(sev[name]) || 0}
            </span>
          ))}
        </div>
      </Tile>

      <Tile
        label="High or critical"
        value={count(serious)}
        sub={`${Number(sev.CRITICAL) || 0} critical · ${Number(sev.HIGH) || 0} high`}
      />

      <Tile
        label="Endpoints online"
        value={`${online}/${(agents || []).length}`}
        sub={`${count(s.sessions_active ?? 0)} PQC session${
          (s.sessions_active ?? 0) === 1 ? "" : "s"
        }`}
      />

      <Tile
        label="Events ingested"
        value={count(s.total_events ?? 0)}
        sub={`${count(s.live_windows ?? 0)} live window${(s.live_windows ?? 0) === 1 ? "" : "s"}`}
      />

      <Tile
        label="Analyst verdicts"
        value={count(rl?.total_feedback ?? 0)}
        sub={`${rl?.n_states_trained ?? 0} of ${rl?.n_states ?? 32} states trained`}
      />
    </div>
  );
}

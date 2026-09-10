import React from "react";
import {
  ShieldAlert,
  Server,
  Activity,
  Cpu,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  Zap,
  CheckCircle2,
  FileText,
  Radio,
} from "lucide-react";
import { Card, Chip, SeverityChip, count, bytes, clockTime, dateTime, humanRule, SEVERITIES } from "../ui.jsx";
import TimelineChart from "../TimelineChart.jsx";
import ScoreChart from "../ScoreChart.jsx";

export default function DashboardView({
  summary,
  agents = [],
  threats = [],
  timeline = [],
  scores = { threshold: null, scores: [] },
  events = [],
  rl,
  onSelectThreat,
  onVerdict,
  pendingVerdict,
  onNavigate,
}) {
  const s = summary || {};
  const sev = s.by_severity || {};
  const stat = s.by_status || {};
  const onlineEndpoints = agents.filter((a) => a.online).length;
  const criticalHighCount = (Number(sev.CRITICAL) || 0) + (Number(sev.HIGH) || 0);

  // Top active threats (open first, newest first)
  const priorityThreats = React.useMemo(() => {
    return [...threats]
      .sort((a, b) => {
        if (a.status === "open" && b.status !== "open") return -1;
        if (a.status !== "open" && b.status === "open") return 1;
        return b.id - a.id;
      })
      .slice(0, 6);
  }, [threats]);

  // Recent 6 events
  const recentEvents = events.slice(0, 6);

  return (
    <div className="page-content">
      {/* Hero Command Section */}
      <section className="hero-banner">
        <div className="hero-tag">
          <Zap size={13} />
          <span>Real-Time Autonomous Cyber Defense</span>
        </div>
        <h1 className="hero-title">Detect. Prevent. Stay Ahead.</h1>
        <p className="hero-subtitle">
          Real-time insider risk detection powered by Isolation Forest anomaly discovery,
          continuous Q-Learning adaptive response, and quantum-resistant ML-KEM telemetry.
        </p>
      </section>

      {/* KPI Metrics Grid */}
      <section className="kpi-grid">
        <div className="kpi-tile hero-tile">
          <div className="kpi-top">
            <span className="kpi-label">Active Threats Queue</span>
            <div className="kpi-icon-wrap">
              <ShieldAlert size={16} />
            </div>
          </div>
          <div className="kpi-value">{count(s.open_threats ?? threats.filter(t => t.status === "open").length)}</div>
          <div className="kpi-sub">
            {count(s.total_threats ?? threats.length)} total detected · {count(stat.blocked ?? 0)} blocked · {count(stat.dismissed ?? 0)} dismissed
          </div>
          <div className="kpi-chips-row">
            {SEVERITIES.map((name) => (
              <span key={name} className={`chip sev-${name}`}>
                <i className="swatch" aria-hidden="true" />
                {name}: {Number(sev[name]) || 0}
              </span>
            ))}
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">Critical & High</span>
            <div className="kpi-icon-wrap">
              <AlertTriangle size={16} />
            </div>
          </div>
          <div className="kpi-value">{count(criticalHighCount)}</div>
          <div className="kpi-sub">
            {Number(sev.CRITICAL) || 0} critical priority · {Number(sev.HIGH) || 0} elevated risk
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">Endpoints Monitored</span>
            <div className="kpi-icon-wrap">
              <Server size={16} />
            </div>
          </div>
          <div className="kpi-value">{`${onlineEndpoints} / ${agents.length}`}</div>
          <div className="kpi-sub">
            {count(s.sessions_active ?? 0)} active PQC encrypted sessions
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">Telemetry Ingested</span>
            <div className="kpi-icon-wrap">
              <Activity size={16} />
            </div>
          </div>
          <div className="kpi-value">{count(s.total_events ?? events.length)}</div>
          <div className="kpi-sub">
            {count(s.live_windows ?? 0)} live observation windows
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">RL Policy State</span>
            <div className="kpi-icon-wrap">
              <Cpu size={16} />
            </div>
          </div>
          <div className="kpi-value">{count(rl?.total_feedback ?? 0)}</div>
          <div className="kpi-sub">
            {rl?.n_states_trained ?? 0} of {rl?.n_states ?? 32} discrete states trained
          </div>
        </div>
      </section>

      {/* Split Analytics: Threat Activity by Hour & Anomaly Score Distribution */}
      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: "20px" }}>
        <TimelineChart timeline={timeline} />
        <ScoreChart scores={scores.scores} threshold={scores.threshold} />
      </section>

      {/* Priority Threat Queue Preview & Live Activity Stream Preview */}
      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(480px, 1fr))", gap: "20px" }}>
        {/* Priority Threats Card */}
        <Card
          title="Active Priority Threats"
          hint={`${priorityThreats.length} shown · click row to inspect in Threats view`}
          actions={
            <button className="btn" onClick={() => onNavigate("threats")}>
              <span>View All Threats</span>
              <ArrowRight size={13} />
            </button>
          }
        >
          {priorityThreats.length === 0 ? (
            <p className="dim" style={{ padding: "20px 0", textAlign: "center" }}>
              No active threats recorded. The queue updates continuously as endpoint telemetry is analyzed.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>User & Host</th>
                    <th>Evidence</th>
                    <th className="num">Score</th>
                    <th className="num">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {priorityThreats.map((t) => {
                    const open = t.status === "open";
                    const busy = pendingVerdict === t.id;
                    const f = t.features || {};
                    return (
                      <tr
                        key={t.id}
                        className="clickable"
                        onClick={() => {
                          onSelectThreat(t.id);
                          onNavigate("threats");
                        }}
                      >
                        <td>
                          <SeverityChip severity={t.severity} />
                        </td>
                        <td className="truncate-sm">
                          <strong>{t.user}</strong>
                          <div className="dim mono" style={{ fontSize: "11px" }}>{t.host}</div>
                        </td>
                        <td>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                            {(t.rules_fired || []).length > 0 ? (
                              t.rules_fired.slice(0, 2).map((r) => (
                                <Chip key={r}>{humanRule(r)}</Chip>
                              ))
                            ) : (
                              <span className="dim">model flagged</span>
                            )}
                          </div>
                          <div className="dim" style={{ fontSize: "10.5px", marginTop: "3px" }}>
                            {count(f.file_count || 0)} files · {bytes(f.file_bytes_total || 0)}
                          </div>
                        </td>
                        <td className="num mono" style={{ fontWeight: 600 }}>
                          {Number(t.anomaly_score).toFixed(3)}
                        </td>
                        <td className="num" onClick={(e) => e.stopPropagation()}>
                          {open ? (
                            <div className="verdicts-group" style={{ justifyContent: "flex-end" }}>
                              <button
                                className="btn-verdict block"
                                disabled={busy}
                                onClick={() => onVerdict(t.id, "block")}
                                title="Contain threat and train RL policy to block"
                              >
                                Block
                              </button>
                              <button
                                className="btn-verdict dismiss"
                                disabled={busy}
                                onClick={() => onVerdict(t.id, "dismiss")}
                                title="Dismiss as false positive"
                              >
                                Dismiss
                              </button>
                            </div>
                          ) : (
                            <span className="dim mono" style={{ fontSize: "11px", textTransform: "uppercase" }}>
                              {t.status}
                            </span>
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

        {/* Live Event Stream Snippet */}
        <Card
          title="Real-Time Endpoint Activity"
          hint={`${recentEvents.length} most recent stream events`}
          actions={
            <button className="btn" onClick={() => onNavigate("activity")}>
              <span>Full Stream</span>
              <ArrowRight size={13} />
            </button>
          }
        >
          {recentEvents.length === 0 ? (
            <p className="dim" style={{ padding: "20px 0", textAlign: "center" }}>
              Awaiting endpoint events. Enrolled endpoints stream encrypted telemetry batches.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Signal</th>
                    <th>User</th>
                    <th>Path / Target</th>
                    <th className="num">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {recentEvents.map((e) => (
                    <tr key={e.id}>
                      <td className="mono dim" style={{ fontSize: "11px" }}>{clockTime(e.ts)}</td>
                      <td>
                        <Chip className="mono">{e.log_type}</Chip>
                      </td>
                      <td className="truncate-sm">{e.user || "—"}</td>
                      <td className="truncate mono dim" title={e.path || ""}>
                        {e.path || "—"}
                      </td>
                      <td className="num mono">{e.size_bytes ? bytes(e.size_bytes) : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </section>
    </div>
  );
}

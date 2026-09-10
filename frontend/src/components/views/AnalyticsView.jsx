import React from "react";
import {
  BarChart3,
  TrendingUp,
  Cpu,
  Layers,
  Clock,
  Shield,
  Activity,
} from "lucide-react";
import { Card, Chip, count, bytes } from "../ui.jsx";
import TimelineChart from "../TimelineChart.jsx";
import ScoreChart from "../ScoreChart.jsx";
import QTablePanel from "../QTablePanel.jsx";

export default function AnalyticsView({
  timeline = [],
  scores = { threshold: null, scores: [] },
  qtable = [],
  rl,
  threats = [],
  events = [],
  onResetPolicy,
}) {
  // Aggregate high level statistics from threats
  const totalThreats = threats.length;
  const afterHoursThreats = threats.filter((t) => t.features?.is_after_hours || t.features?.after_hours).length;
  const usbInvolvedThreats = threats.filter((t) => Number(t.features?.usb_connect || 0) > 0).length;
  const avgAnomalyScore = totalThreats > 0
    ? (threats.reduce((acc, t) => acc + (Number(t.anomaly_score) || 0), 0) / totalThreats).toFixed(3)
    : "—";

  return (
    <div className="page-content">
      {/* Overview Header */}
      <div>
        <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
          Threat & Telemetry Analytics
        </h1>
        <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
          Statistical distributions and reinforcement learning policy convergence metrics across all monitored endpoint windows.
        </p>
      </div>

      {/* Analytics Metric Summary Cards */}
      <section className="kpi-grid">
        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">After-Hours Activity</span>
            <div className="kpi-icon-wrap">
              <Clock size={16} />
            </div>
          </div>
          <div className="kpi-value">{totalThreats ? `${Math.round((afterHoursThreats / totalThreats) * 100)}%` : "0%"}</div>
          <div className="kpi-sub">
            {count(afterHoursThreats)} of {count(totalThreats)} threat windows outside standard operating hours
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">Removable / USB Risk</span>
            <div className="kpi-icon-wrap">
              <Shield size={16} />
            </div>
          </div>
          <div className="kpi-value">{count(usbInvolvedThreats)}</div>
          <div className="kpi-sub">
            Windows involving removable flash drives or external peripheral connections
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">Average Anomaly Score</span>
            <div className="kpi-icon-wrap">
              <Activity size={16} />
            </div>
          </div>
          <div className="kpi-value mono">{avgAnomalyScore}</div>
          <div className="kpi-sub">
            Decision boundary threshold: {Number(scores.threshold ?? 0).toFixed(3)}
          </div>
        </div>

        <div className="kpi-tile">
          <div className="kpi-top">
            <span className="kpi-label">RL Policy Convergence</span>
            <div className="kpi-icon-wrap">
              <Cpu size={16} />
            </div>
          </div>
          <div className="kpi-value">
            {rl ? `${Math.round(((rl.n_states_trained || 0) / (rl.n_states || 32)) * 100)}%` : "0%"}
          </div>
          <div className="kpi-sub">
            {rl?.n_states_trained ?? 0} of {rl?.n_states ?? 32} discrete behavioral states trained
          </div>
        </div>
      </section>

      {/* 24-Hour Timeline & Isolation Forest Score Histogram */}
      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: "20px" }}>
        <TimelineChart timeline={timeline} />
        <ScoreChart scores={scores.scores} threshold={scores.threshold} />
      </section>

      {/* Q-Table Policy Matrix */}
      <section>
        <QTablePanel
          table={qtable}
          stats={rl}
          onReset={onResetPolicy}
        />
      </section>
    </div>
  );
}

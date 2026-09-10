import React from "react";
import {
  ShieldAlert,
  Search,
  CheckCircle2,
  Filter,
  Layers,
  Zap,
  Activity,
  User,
  Clock,
  Laptop,
} from "lucide-react";
import { Card, Chip, SeverityChip, count, bytes, clockTime, dateTime, humanRule, SEVERITIES } from "../ui.jsx";

const STATUS_FILTERS = [
  { key: "all", label: "All Statuses" },
  { key: "open", label: "Open Only" },
  { key: "blocked", label: "Blocked" },
  { key: "dismissed", label: "Dismissed" },
];

const PRIMARY_FEATURES = [
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

function parseState(state) {
  const vol = ["none", "low", "medium", "high"];
  const m = /^ah([01])\|usb([01])\|vol([0-3])\|anom([01])$/.exec(state || "");
  if (!m) return null;
  return [
    ["After hours", m[1] === "1" ? "Yes" : "No"],
    ["USB present", m[2] === "1" ? "Yes" : "No"],
    ["File volume", vol[Number(m[3])]],
    ["Anomaly flagged", m[4] === "1" ? "Anomalous" : "Normal"],
  ];
}

export default function ThreatsView({
  threats = [],
  selectedId,
  onSelectThreat,
  detail,
  detailLoading,
  onVerdict,
  pendingVerdict,
}) {
  const [search, setSearch] = React.useState("");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [severityFilter, setSeverityFilter] = React.useState("all");

  const filteredThreats = React.useMemo(() => {
    const floor = SEVERITIES.indexOf(severityFilter);
    const q = search.trim().toLowerCase();

    return threats.filter((t) => {
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (floor >= 0 && SEVERITIES.indexOf(t.severity) < floor) return false;
      if (q) {
        const matchUser = (t.user || "").toLowerCase().includes(q);
        const matchHost = (t.host || "").toLowerCase().includes(q);
        const matchAgent = (t.agent_id || "").toLowerCase().includes(q);
        const matchRule = (t.rules_fired || []).some((r) => r.toLowerCase().includes(q));
        if (!matchUser && !matchHost && !matchAgent && !matchRule) return false;
      }
      return true;
    });
  }, [threats, statusFilter, severityFilter, search]);

  const activeThreat = detail || threats.find((t) => t.id === selectedId);

  return (
    <div className="page-content">
      {/* Top Filter Bar */}
      <div className="filters-bar">
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          {/* Status tabs */}
          <div className="tabs-group" role="tablist">
            {STATUS_FILTERS.map((f) => (
              <button
                key={f.key}
                className={`tab-btn ${statusFilter === f.key ? "active" : ""}`}
                onClick={() => setStatusFilter(f.key)}
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Severity selector */}
          <div className="select-wrap">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              aria-label="Filter by minimum severity"
            >
              <option value="all">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High and above</option>
              <option value="MEDIUM">Medium and above</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {/* Search Bar */}
        <div className="search-input-wrap">
          <Search size={14} />
          <input
            type="text"
            className="input-search"
            placeholder="Search host, user, rule..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Main Investigation Split View: Table + Threat X-Ray Detail */}
      <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "20px", alignItems: "start" }}>
        {/* Threat Queue Table */}
        <Card
          title="Threat Investigation Queue"
          hint={`${filteredThreats.length} threat windows`}
        >
          {filteredThreats.length === 0 ? (
            <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
              No threats match your current filters.
            </p>
          ) : (
            <div className="table-wrap" style={{ maxHeight: "calc(100vh - 280px)", overflowY: "auto" }}>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Detected</th>
                    <th>User & Host</th>
                    <th>Evidence</th>
                    <th className="num">Score</th>
                    <th className="num">Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredThreats.map((t) => {
                    const isSelected = selectedId === t.id;
                    const isOpen = t.status === "open";
                    const busy = pendingVerdict === t.id;
                    const f = t.features || {};

                    return (
                      <tr
                        key={t.id}
                        className={`clickable ${isSelected ? "selected" : ""}`}
                        onClick={() => onSelectThreat(t.id)}
                      >
                        <td>
                          <SeverityChip severity={t.severity} />
                        </td>
                        <td className="mono dim nowrap" style={{ fontSize: "11px" }}>
                          {clockTime(t.created_at)}
                        </td>
                        <td className="truncate-sm">
                          <strong>{t.user}</strong>
                          <div className="dim mono" style={{ fontSize: "11px" }}>@{t.host}</div>
                        </td>
                        <td>
                          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                            {(t.rules_fired || []).length > 0 ? (
                              t.rules_fired.map((r) => <Chip key={r}>{humanRule(r)}</Chip>)
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
                          {isOpen ? (
                            <div className="verdicts-group" style={{ justifyContent: "flex-end" }}>
                              <button
                                className="btn-verdict block"
                                disabled={busy}
                                onClick={() => onVerdict(t.id, "block")}
                                title="Block action & teach policy"
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

        {/* Threat X-Ray Detail Panel */}
        <Card
          title={activeThreat ? `Threat #${activeThreat.id} X-Ray` : "Threat X-Ray"}
          hint={activeThreat ? dateTime(activeThreat.created_at) : "Select a threat row to inspect full telemetry"}
          actions={activeThreat && <SeverityChip severity={activeThreat.severity} />}
        >
          {detailLoading ? (
            <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
              Loading threat signals and policy parameters...
            </p>
          ) : !activeThreat ? (
            <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
              Click any threat in the queue to inspect anomaly signals, window features, and Q-learning policy decisions.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
              {/* Disposition Action Bar */}
              <div
                style={{
                  padding: "12px 14px",
                  borderRadius: "var(--radius-md)",
                  background: "rgba(255, 255, 255, 0.03)",
                  border: "1px solid var(--border-subtle)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <span className="dim" style={{ fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                    Current Disposition
                  </span>
                  <div style={{ fontSize: "14px", fontWeight: 600, color: "#ffffff", marginTop: "2px" }}>
                    {activeThreat.status.toUpperCase()}
                  </div>
                </div>

                {activeThreat.status === "open" && (
                  <div className="verdicts-group">
                    <button
                      className="btn-verdict block"
                      disabled={pendingVerdict === activeThreat.id}
                      onClick={() => onVerdict(activeThreat.id, "block")}
                    >
                      Confirm & Block
                    </button>
                    <button
                      className="btn-verdict dismiss"
                      disabled={pendingVerdict === activeThreat.id}
                      onClick={() => onVerdict(activeThreat.id, "dismiss")}
                    >
                      Dismiss (Benign)
                    </button>
                  </div>
                )}
              </div>

              {/* Endpoint Context Metadata */}
              <div>
                <h3 style={{ fontSize: "11.5px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "8px" }}>
                  Endpoint Identity
                </h3>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", fontSize: "12.5px" }}>
                  <div>
                    <span className="dim">User:</span> <strong>{activeThreat.user}</strong>
                  </div>
                  <div>
                    <span className="dim">Host:</span> <span className="mono">{activeThreat.host}</span>
                  </div>
                  <div>
                    <span className="dim">Agent ID:</span> <span className="mono">{activeThreat.agent_id}</span>
                  </div>
                  <div>
                    <span className="dim">Anomaly Score:</span> <span className="mono">{Number(activeThreat.anomaly_score).toFixed(4)}</span>
                  </div>
                </div>
              </div>

              {/* Rules Triggered */}
              <div>
                <h3 style={{ fontSize: "11.5px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "8px" }}>
                  Fired Heuristic Rules
                </h3>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                  {(activeThreat.rules_fired || []).length > 0 ? (
                    activeThreat.rules_fired.map((r) => (
                      <Chip key={r} className="mono">{humanRule(r)}</Chip>
                    ))
                  ) : (
                    <span className="dim" style={{ fontSize: "12px" }}>
                      None — identified purely by Isolation Forest unsupervised anomaly detection.
                    </span>
                  )}
                </div>
              </div>

              {/* Decision State Breakdown */}
              {activeThreat.state && (
                <div>
                  <h3 style={{ fontSize: "11.5px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "8px" }}>
                    Q-Learning State (<span className="mono">{activeThreat.state}</span>)
                  </h3>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "12px" }}>
                    {parseState(activeThreat.state)?.map(([k, v]) => (
                      <div key={k} style={{ padding: "6px 10px", background: "rgba(255, 255, 255, 0.03)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                        <span className="dim">{k}:</span> <strong> {v}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Policy Q-Values Now */}
              {activeThreat.policy?.q_values && (
                <div>
                  <h3 style={{ fontSize: "11.5px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "8px" }}>
                    Learned Response Values (Q-Values)
                  </h3>
                  <table style={{ background: "rgba(255,255,255,0.02)", borderRadius: "var(--radius-sm)" }}>
                    <thead>
                      <tr>
                        <th>Action</th>
                        <th className="num">Q-Value</th>
                        <th>Recommended</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(activeThreat.policy.q_values).map(([act, val]) => (
                        <tr key={act}>
                          <td className="mono" style={{ fontWeight: act === activeThreat.policy.action ? 700 : 400 }}>{act}</td>
                          <td className="num mono">{Number(val).toFixed(3)}</td>
                          <td>
                            {act === activeThreat.policy.action && (
                              <span className="chip plain" style={{ background: "#ffffff", color: "#000000" }}>Optimal</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Window Features */}
              {activeThreat.features && (
                <div>
                  <h3 style={{ fontSize: "11.5px", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)", marginBottom: "8px" }}>
                    Observation Window Telemetry
                  </h3>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "12px" }}>
                    {PRIMARY_FEATURES.filter(([k]) => activeThreat.features[k] !== undefined).map(([k, label, fmt]) => (
                      <div key={k} style={{ padding: "6px 10px", background: "rgba(255, 255, 255, 0.02)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)" }}>
                        <span className="dim">{label}:</span> <strong className="mono">{fmt(activeThreat.features[k])}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

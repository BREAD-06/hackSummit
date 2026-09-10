import React from "react";
import {
  Users,
  KeyRound,
  Copy,
  Check,
  Server,
  FileCode,
  ShieldCheck,
  Terminal,
  Layers,
} from "lucide-react";
import { Card, Chip, count, ago, dateTime } from "../ui.jsx";

export default function AgentsView({
  agents = [],
  onEnrollToken,
}) {
  const [tokenData, setTokenData] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const mint = async () => {
    setBusy(true);
    try {
      const res = await onEnrollToken();
      if (res) setTokenData(res);
    } finally {
      setBusy(false);
    }
  };

  const copyToken = () => {
    if (tokenData?.token) {
      navigator.clipboard.writeText(tokenData.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const onlineCount = agents.filter((a) => a.online).length;

  return (
    <div className="page-content">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
            Agent Fleet Management
          </h1>
          <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
            Enroll, monitor, and configure post-quantum endpoint telemetry collection agents.
          </p>
        </div>

        <button className="btn btn-primary" disabled={busy} onClick={mint}>
          <KeyRound size={14} />
          <span>{busy ? "Minting..." : "Mint Enrollment Token"}</span>
        </button>
      </div>

      {/* Active Token Banner if minted */}
      {tokenData && (
        <div className="banner learned" style={{ flexDirection: "column", alignItems: "flex-start" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
            <span style={{ fontWeight: 600, color: "#ffffff" }}>One-Time Enrollment Token Generated</span>
            <button className="banner-close" onClick={() => setTokenData(null)}>×</button>
          </div>
          <div
            style={{
              marginTop: "8px",
              padding: "8px 12px",
              background: "rgba(0,0,0,0.6)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border-medium)",
              width: "100%",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <span className="mono" style={{ fontSize: "12px", color: "#ffffff", wordBreak: "break-all" }}>
              {tokenData.token}
            </span>
            <button className="btn btn-icon" onClick={copyToken} title="Copy token">
              {copied ? <Check size={14} color="#ffffff" /> : <Copy size={14} />}
            </button>
          </div>
          <p className="dim" style={{ fontSize: "11.5px", marginTop: "6px" }}>
            Place this token in <span className="mono">agent_config.yaml</span> on the target machine as <span className="mono">enroll_token</span>.
          </p>
        </div>
      )}

      {/* Agents Table */}
      <Card
        title="Registered Agents"
        hint={`${onlineCount} active / ${agents.length} total`}
      >
        {agents.length === 0 ? (
          <p className="dim" style={{ padding: "30px 0", textAlign: "center" }}>
            No agents registered yet. Mint an enrollment token above and start an endpoint collector.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Hostname</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                  <th className="num">Batches</th>
                  <th className="num">Events</th>
                  <th>Enrolled On</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agent_id}>
                    <td className="mono" style={{ fontWeight: 600, color: "#ffffff" }}>
                      {a.agent_id}
                    </td>
                    <td>{a.host || "—"}</td>
                    <td>
                      <div style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
                        <i className={`dot ${a.online ? "live" : "offline"}`} />
                        <span style={{ fontSize: "12px", color: a.online ? "#ffffff" : "var(--dim)" }}>
                          {a.online ? "Active Session" : "Offline"}
                        </span>
                      </div>
                    </td>
                    <td className="dim nowrap" title={dateTime(a.last_seen)}>
                      {ago(a.last_seen)}
                    </td>
                    <td className="num mono">{a.session ? count(a.session.batches) : "—"}</td>
                    <td className="num mono">{a.session ? count(a.session.events) : "—"}</td>
                    <td className="dim nowrap">{dateTime(a.enrolled_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Agent Configuration Guide */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "20px" }}>
        <Card
          title="Agent Deployment Instructions"
          hint="Zero-privilege metadata collector setup"
          icon={<FileCode size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12.5px", color: "var(--ink-secondary)", lineHeight: "1.6" }}>
            <p>
              The VIGIL AI Endpoint Agent operates with least-privilege telemetry:
            </p>
            <ul style={{ paddingLeft: "18px" }}>
              <li><strong>Zero Content Inspection:</strong> Analyzes file names, sizes, access velocity, and paths — never reads document contents.</li>
              <li><strong>Post-Quantum Tunnel:</strong> Encapsulates payload keys with <strong>ML-KEM-512</strong> and signs batches with <strong>ML-DSA-44</strong> before leaving the machine.</li>
              <li><strong>Simulated Containment:</strong> When a policy blocks an action, it issues an alert and local audit log rather than forcibly severing network adapters.</li>
            </ul>
          </div>
        </Card>

        <Card
          title="agent_config.yaml Template"
          hint="Local configuration file syntax"
          icon={<Terminal size={16} />}
        >
          <pre
            className="mono"
            style={{
              padding: "12px",
              background: "rgba(0,0,0,0.6)",
              borderRadius: "var(--radius-sm)",
              border: "1px solid var(--border-subtle)",
              fontSize: "11px",
              color: "#d4d4d8",
              lineHeight: "1.5",
              overflowX: "auto",
            }}
          >
{`server_url: "https://your-soc-host.domain"
enroll_token: "PASTE_MINTED_TOKEN_HERE"
agent_id: "AGENT-WKS-01"

collectors:
  file_access: true
  usb_events: true
  logon_sessions: true
  watch_path: "C:\\Users\\Public\\Documents"

flush_interval_seconds: 5`}
          </pre>
        </Card>
      </div>
    </div>
  );
}

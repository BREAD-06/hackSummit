import React from "react";
import {
  Server,
  KeyRound,
  Search,
  CheckCircle2,
  Copy,
  Check,
  Radio,
  Clock,
  Shield,
  Layers,
} from "lucide-react";
import { Card, Chip, count, bytes, ago, dateTime, Modal } from "../ui.jsx";

export default function EndpointsView({
  agents = [],
  onEnrollToken,
}) {
  const [search, setSearch] = React.useState("");
  const [filterStatus, setFilterStatus] = React.useState("all");
  const [tokenData, setTokenData] = React.useState(null);
  const [isMinting, setIsMinting] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const onlineCount = agents.filter((a) => a.online).length;

  const filteredAgents = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return agents.filter((a) => {
      if (filterStatus === "online" && !a.online) return false;
      if (filterStatus === "offline" && a.online) return false;
      if (q) {
        const matchId = (a.agent_id || "").toLowerCase().includes(q);
        const matchHost = (a.host || "").toLowerCase().includes(q);
        if (!matchId && !matchHost) return false;
      }
      return true;
    });
  }, [agents, filterStatus, search]);

  const handleMintToken = async () => {
    setIsMinting(true);
    try {
      const res = await onEnrollToken();
      if (res) setTokenData(res);
    } finally {
      setIsMinting(false);
    }
  };

  const handleCopyToken = () => {
    if (tokenData?.token) {
      navigator.clipboard.writeText(tokenData.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="page-content">
      {/* Top Banner & Action */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
            Monitored Endpoints
          </h1>
          <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
            {onlineCount} of {agents.length} endpoint agents online with active post-quantum cryptographic sessions.
          </p>
        </div>

        <button className="btn btn-primary" onClick={handleMintToken} disabled={isMinting}>
          <KeyRound size={14} />
          <span>{isMinting ? "Minting Token..." : "Enroll New Endpoint"}</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="filters-bar">
        <div className="tabs-group">
          {[
            ["all", "All Agents"],
            ["online", `Online (${onlineCount})`],
            ["offline", `Offline (${agents.length - onlineCount})`],
          ].map(([key, label]) => (
            <button
              key={key}
              className={`tab-btn ${filterStatus === key ? "active" : ""}`}
              onClick={() => setFilterStatus(key)}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="search-input-wrap">
          <Search size={14} />
          <input
            type="text"
            className="input-search"
            placeholder="Filter by host or agent ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Endpoints Table */}
      <Card
        title="Agent Fleet Roster"
        hint={`${filteredAgents.length} endpoints listed`}
      >
        {filteredAgents.length === 0 ? (
          <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
            No endpoints match the search criteria. Mint an enrollment token to onboard a new endpoint agent.
          </p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Agent ID</th>
                  <th>Host Machine</th>
                  <th>Last Seen</th>
                  <th className="num">Batches</th>
                  <th className="num">Events</th>
                  <th className="num">Last Seq</th>
                  <th>Crypto Session</th>
                </tr>
              </thead>
              <tbody>
                {filteredAgents.map((a) => {
                  const s = a.session;
                  return (
                    <tr key={a.agent_id}>
                      <td className="nowrap">
                        <div style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
                          <i className={`dot ${a.online ? "live" : "offline"}`} />
                          <span style={{ fontSize: "12px", fontWeight: 500, color: a.online ? "#ffffff" : "var(--dim)" }}>
                            {a.online ? "Online" : "Offline"}
                          </span>
                        </div>
                      </td>
                      <td className="mono" style={{ fontWeight: 600, color: "#ffffff" }}>
                        {a.agent_id}
                      </td>
                      <td>{a.host || "—"}</td>
                      <td className="nowrap dim" title={dateTime(a.last_seen)}>
                        {ago(a.last_seen)}
                      </td>
                      <td className="num mono">{s ? count(s.batches) : "—"}</td>
                      <td className="num mono">{s ? count(s.events) : "—"}</td>
                      <td className="num mono">{s ? count(s.last_seq) : "—"}</td>
                      <td className="nowrap dim" style={{ fontSize: "11.5px" }}>
                        {s ? (
                          <span>
                            <span className="mono">{s.key_bits}-bit AES-GCM</span> (active since {dateTime(s.established_at)})
                          </span>
                        ) : (
                          <span>Enrolled {dateTime(a.enrolled_at)} — no live session</span>
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

      {/* Token Enrollment Modal */}
      <Modal
        isOpen={Boolean(tokenData)}
        onClose={() => setTokenData(null)}
        title="One-Time Agent Enrollment Token"
      >
        <p className="dim" style={{ fontSize: "12.5px", lineHeight: "1.5" }}>
          This single-use cryptographic token authorizes an endpoint agent to establish a certified post-quantum identity with the VIGIL detection server.
        </p>

        <div
          style={{
            padding: "12px",
            background: "rgba(0,0,0,0.5)",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-md)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "10px",
          }}
        >
          <span className="mono" style={{ fontSize: "12px", color: "#ffffff", wordBreak: "break-all" }}>
            {tokenData?.token}
          </span>
          <button className="btn btn-icon" onClick={handleCopyToken} title="Copy Token">
            {copied ? <Check size={14} color="#ffffff" /> : <Copy size={14} />}
          </button>
        </div>

        <div style={{ fontSize: "12px", color: "var(--muted)", lineHeight: "1.6" }}>
          <strong>How to install on agent:</strong>
          <ol style={{ paddingLeft: "18px", marginTop: "4px" }}>
            <li>Copy the token above.</li>
            <li>Paste into the endpoint agent's <span className="mono">agent_config.yaml</span> as <span className="mono">enroll_token</span>.</li>
            <li>Run <span className="mono">python -m agent.main</span> to perform the initial ML-KEM handshake.</li>
          </ol>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "12px" }}>
          <button className="btn btn-primary" onClick={() => setTokenData(null)}>
            Done
          </button>
        </div>
      </Modal>
    </div>
  );
}

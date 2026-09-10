import React from "react";
import { RefreshCw, KeyRound, Shield, Search, Terminal } from "lucide-react";

const ROUTE_TITLES = {
  dashboard: "Command Overview",
  threats: "Active Threats Queue",
  endpoints: "Monitored Endpoints",
  analytics: "Insider Risk Analytics",
  agents: "Agent Fleet Management",
  policy: "Enterprise Policy Center",
  security: "Post-Quantum Security Architecture",
  activity: "Real-time Telemetry Stream",
  settings: "SOC Console Configuration",
};

export default function Header({
  currentRoute,
  conn,
  onRefresh,
  onMintToken,
  refreshing,
}) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="page-title-badge">
          <Shield size={16} color="#ffffff" />
          <span>{ROUTE_TITLES[currentRoute] || "Overview"}</span>
        </div>
      </div>

      <div className="topbar-right">
        {/* Connection status */}
        <div className="live-pill" title={`WebSocket Status: ${conn}`}>
          <i className={`dot ${conn === "live" ? "live" : conn === "offline" ? "offline" : "connecting"}`} />
          <span>{conn === "live" ? "Live Feed" : conn === "offline" ? "Disconnected" : "Connecting..."}</span>
        </div>

        {/* Enroll Endpoint shortcut */}
        <button
          className="btn"
          onClick={onMintToken}
          title="Mint a one-time endpoint enrollment token"
        >
          <KeyRound size={14} />
          <span>Enroll Agent</span>
        </button>

        {/* Refresh button */}
        <button
          className="btn btn-icon"
          onClick={onRefresh}
          disabled={refreshing}
          title="Fetch latest updates from server"
          aria-label="Refresh data"
        >
          <RefreshCw size={14} className={refreshing ? "spin" : ""} />
        </button>
      </div>
    </header>
  );
}

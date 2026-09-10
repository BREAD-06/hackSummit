import React from "react";
import {
  Shield,
  LayoutDashboard,
  ShieldAlert,
  Server,
  BarChart3,
  Users,
  Lock,
  Activity,
  Settings,
  ChevronLeft,
  ChevronRight,
  Radio,
  Cpu,
  Sliders,
} from "lucide-react";

export default function Sidebar({
  currentRoute,
  onNavigate,
  collapsed,
  onToggleCollapse,
  conn,
  kem,
  openThreatsCount = 0,
  onlineEndpointsCount = 0,
}) {
  const navGroups = [
    {
      label: "Monitoring",
      items: [
        {
          id: "dashboard",
          label: "Dashboard",
          icon: LayoutDashboard,
        },
        {
          id: "threats",
          label: "Threats",
          icon: ShieldAlert,
          badge: openThreatsCount > 0 ? openThreatsCount : null,
        },
        {
          id: "endpoints",
          label: "Endpoints",
          icon: Server,
          badge: onlineEndpointsCount > 0 ? `${onlineEndpointsCount} live` : null,
        },
        {
          id: "analytics",
          label: "Analytics",
          icon: BarChart3,
        },
      ],
    },
    {
      label: "Operations",
      items: [
        {
          id: "agents",
          label: "Agent Management",
          icon: Users,
        },
        {
          id: "policy",
          label: "Policy Center",
          icon: Sliders,
        },
        {
          id: "security",
          label: "Security / PQC",
          icon: Lock,
        },
        {
          id: "activity",
          label: "Activity",
          icon: Activity,
        },
      ],
    },
    {
      label: "System",
      items: [
        {
          id: "settings",
          label: "Settings",
          icon: Settings,
        },
      ],
    },
  ];

  return (
    <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
      {/* Brand Header */}
      <div className="sidebar-header">
        <div
          className="brand-wrapper"
          onClick={() => onNavigate("dashboard")}
          title="VIGIL AI — Insider Risk Detection"
        >
          <div className="brand-logo-frame">
            <Shield size={18} color="#ffffff" />
          </div>
          {!collapsed && (
            <div className="brand-text">
              <span className="brand-title">VIGIL AI</span>
              <span className="brand-subtitle">Insider Risk SOC</span>
            </div>
          )}
        </div>
        <button
          className="sidebar-collapse-btn"
          onClick={onToggleCollapse}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      {/* Nav groups */}
      <nav className="sidebar-nav">
        {navGroups.map((group) => (
          <div key={group.label} className="nav-group">
            {!collapsed && <span className="nav-group-label">{group.label}</span>}
            {group.items.map((item) => {
              const Icon = item.icon;
              const isActive = currentRoute === item.id;
              return (
                <button
                  key={item.id}
                  className={`nav-item ${isActive ? "active" : ""}`}
                  onClick={() => onNavigate(item.id)}
                  title={collapsed ? item.label : undefined}
                >
                  <span className="nav-item-icon">
                    <Icon size={18} strokeWidth={isActive ? 2.2 : 1.8} />
                  </span>
                  {!collapsed && (
                    <>
                      <span>{item.label}</span>
                      {item.badge && <span className="nav-badge">{item.badge}</span>}
                    </>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer / Telemetry Status Dock */}
      {!collapsed && (
        <div className="sidebar-footer">
          <div className="status-card">
            <div className="status-line">
              <span className="status-label">
                <i className={`dot ${conn === "live" ? "live" : conn === "offline" ? "offline" : "connecting"}`} />
                {conn === "live" ? "SOC Connected" : conn === "offline" ? "SOC Disconnected" : "Connecting..."}
              </span>
              <Radio size={12} color="var(--muted)" />
            </div>
            {kem && (
              <div className="status-line">
                <span className="dim" style={{ fontSize: "10.5px" }}>PQC Channel</span>
                <span className="pqc-pill">{kem}</span>
              </div>
            )}
          </div>

          <div className="operator-profile">
            <div className="operator-avatar">OP</div>
            <div className="operator-meta">
              <span className="operator-name">Security Lead</span>
              <span className="operator-role">SOC Level 3 Operator</span>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}

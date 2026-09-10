import React from "react";
import {
  Activity,
  Search,
  Filter,
  Radio,
  FileText,
  Usb,
  LogIn,
  Layers,
  Clock,
  Terminal,
} from "lucide-react";
import { Card, Chip, count, bytes, clockTime, dateTime } from "../ui.jsx";

const SIGNAL_TYPES = [
  { key: "all", label: "All Signals", icon: Layers },
  { key: "file", label: "File Ops", icon: FileText },
  { key: "usb", label: "USB Events", icon: Usb },
  { key: "logon", label: "Logon / Auth", icon: LogIn },
];

function parseDetail(event) {
  if (!event.detail) return {};
  if (typeof event.detail === "object") return event.detail;
  try {
    return JSON.parse(event.detail);
  } catch {
    return { raw: String(event.detail) };
  }
}

export default function ActivityView({ events = [] }) {
  const [activeType, setActiveType] = React.useState("all");
  const [search, setSearch] = React.useState("");

  const filteredEvents = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return events.filter((e) => {
      if (activeType !== "all" && e.log_type !== activeType) return false;
      if (q) {
        const matchUser = (e.user || "").toLowerCase().includes(q);
        const matchPath = (e.path || "").toLowerCase().includes(q);
        const matchAction = (e.action || "").toLowerCase().includes(q);
        if (!matchUser && !matchPath && !matchAction) return false;
      }
      return true;
    });
  }, [events, activeType, search]);

  return (
    <div className="page-content">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
            Real-Time Activity Telemetry
          </h1>
          <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
            Decrypted and verified endpoint event stream. Only access metadata crosses the wire — file contents are never read.
          </p>
        </div>

        <div className="live-pill">
          <i className="dot live" />
          <span>Real-time Ingest Active</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="filters-bar">
        <div className="tabs-group">
          {SIGNAL_TYPES.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                className={`tab-btn ${activeType === t.key ? "active" : ""}`}
                onClick={() => setActiveType(t.key)}
                style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}
              >
                <Icon size={12} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        <div className="search-input-wrap">
          <Search size={14} />
          <input
            type="text"
            className="input-search"
            placeholder="Search path, user, action..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Activity Table */}
      <Card
        title="Live Signal Feed"
        hint={`${filteredEvents.length} events matching filter`}
      >
        {filteredEvents.length === 0 ? (
          <p className="dim" style={{ padding: "40px 0", textAlign: "center" }}>
            No activity matches the filter. Incoming endpoint events stream directly into this view via WebSocket.
          </p>
        ) : (
          <div className="table-wrap" style={{ maxHeight: "calc(100vh - 280px)", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Signal</th>
                  <th>Action</th>
                  <th>User</th>
                  <th>Target Path / Device</th>
                  <th className="num">Size</th>
                  <th>Metadata Flags</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((e) => {
                  const d = parseDetail(e);
                  return (
                    <tr key={e.id}>
                      <td className="mono dim nowrap" style={{ fontSize: "11px" }}>
                        {clockTime(e.ts)}
                      </td>
                      <td>
                        <Chip className="mono">{e.log_type}</Chip>
                      </td>
                      <td className="mono" style={{ color: "#ffffff", fontWeight: 500 }}>
                        {e.action}
                      </td>
                      <td className="truncate-sm">
                        <strong>{e.user || "—"}</strong>
                      </td>
                      <td className="truncate mono dim" title={e.path || ""}>
                        {e.path || d.drive || d.terminal || "—"}
                      </td>
                      <td className="num mono">
                        {e.size_bytes ? bytes(e.size_bytes) : "—"}
                      </td>
                      <td>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                          {d.sensitive && <Chip className="plain">sensitive</Chip>}
                          {d.removable && <Chip className="plain">removable</Chip>}
                          {d.writes_coalesced > 1 && (
                            <Chip title="Writes collapsed within flush interval">
                              ×{d.writes_coalesced}
                            </Chip>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

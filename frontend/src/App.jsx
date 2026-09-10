import React from "react";

import { ApiError, api, connectLiveFeed } from "./api.js";
import Sidebar from "./components/Sidebar.jsx";
import Header from "./components/Header.jsx";
import DashboardView from "./components/views/DashboardView.jsx";
import ThreatsView from "./components/views/ThreatsView.jsx";
import EndpointsView from "./components/views/EndpointsView.jsx";
import AnalyticsView from "./components/views/AnalyticsView.jsx";
import AgentsView from "./components/views/AgentsView.jsx";
import SecurityView from "./components/views/SecurityView.jsx";
import ActivityView from "./components/views/ActivityView.jsx";
import SettingsView from "./components/views/SettingsView.jsx";
import PolicyCenterView from "./components/views/PolicyCenterView.jsx";
import { Modal } from "./components/ui.jsx";
import { Copy, Check } from "lucide-react";

/**
 * VIGIL AI — INSIDER RISK DETECTION & SOC CONSOLE
 * Fully redesigned Apple/Linear-grade monochrome cybersecurity command center.
 */
export default function App() {
  const [currentRoute, setCurrentRoute] = React.useState("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const [conn, setConn] = React.useState("connecting");
  const [error, setError] = React.useState(null);
  const [learned, setLearned] = React.useState(null);

  // Core Data
  const [summary, setSummary] = React.useState(null);
  const [threats, setThreats] = React.useState([]);
  const [timeline, setTimeline] = React.useState([]);
  const [scores, setScores] = React.useState({ threshold: null, scores: [] });
  const [agents, setAgents] = React.useState([]);
  const [events, setEvents] = React.useState([]);
  const [qtable, setQtable] = React.useState([]);
  const [rl, setRl] = React.useState(null);
  const [pqc, setPqc] = React.useState(null);
  const [health, setHealth] = React.useState(null);
  const [model, setModel] = React.useState(null);

  // Selection & Detail
  const [selectedId, setSelectedId] = React.useState(null);
  const [detail, setDetail] = React.useState(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [pending, setPending] = React.useState(null);

  // Global Quick Enrollment Token Modal
  const [quickToken, setQuickToken] = React.useState(null);
  const [copiedToken, setCopiedToken] = React.useState(false);

  const fail = React.useCallback((err) => {
    setError(err instanceof ApiError ? err.message : String(err?.message || err));
  }, []);

  // ── loaders ────────────────────────────────────────────────────────────────
  const loadThreatData = React.useCallback(async () => {
    const [t, tl, sc] = await Promise.all([
      api.threats({ limit: 200 }),
      api.timeline(),
      api.scores(),
    ]);
    setThreats(t);
    setTimeline(tl);
    setScores(sc);
  }, []);

  const loadRl = React.useCallback(async () => {
    const [q, s] = await Promise.all([api.qtable(), api.rlStats()]);
    setQtable(q.table);
    setRl(s);
  }, []);

  const loadLive = React.useCallback(async () => {
    const [a, e, h, sm] = await Promise.all([
      api.agents(),
      api.recentEvents(80),
      api.health(),
      api.summary(),
    ]);
    setAgents(a);
    setEvents(e);
    setHealth(h);
    setSummary(sm);
  }, []);

  const loadAll = React.useCallback(async () => {
    setRefreshing(true);
    try {
      await Promise.all([
        loadThreatData(),
        loadRl(),
        loadLive(),
        api.pqc().then(setPqc),
        api.model().then(setModel),
      ]);
      setError(null);
    } catch (err) {
      fail(err);
    } finally {
      setRefreshing(false);
    }
  }, [loadThreatData, loadRl, loadLive, fail]);

  React.useEffect(() => {
    loadAll();
  }, [loadAll]);

  // Periodic poll for agent silence
  React.useEffect(() => {
    const id = setInterval(() => {
      loadLive().catch(() => {});
    }, 20000);
    return () => clearInterval(id);
  }, [loadLive]);

  // ── live feed ──────────────────────────────────────────────────────────────
  React.useEffect(() => {
    const close = connectLiveFeed({
      onStatus: (s) => {
        setConn(s);
        if (s === "live") setError(null);
      },
      onMessage: (msg) => {
        const { type, data } = msg;
        if (type === "hello" || type === "summary") {
          if (data?.summary) setSummary(data.summary);
          else if (data) setSummary(data);
          return;
        }
        if (type === "threat" || type === "threat_update") {
          setThreats((prev) => {
            const rest = prev.filter((t) => t.id !== data.id);
            return [data, ...rest].sort((a, b) => b.id - a.id).slice(0, 200);
          });
          api.timeline().then(setTimeline).catch(() => {});
          api.scores().then(setScores).catch(() => {});
          api.recentEvents(80).then(setEvents).catch(() => {});
          return;
        }
        if (type === "feedback") {
          setThreats((prev) =>
            prev.map((t) => (t.id === data.threat_id ? { ...t, status: data.status } : t)),
          );
          setLearned(data);
          loadRl().catch(() => {});
          return;
        }
        if (type === "rl_update" || type === "rl_reset") {
          setRl(data);
          api.qtable().then((q) => setQtable(q.table)).catch(() => {});
          return;
        }
        if (type === "agent_enrolled" || type === "agent_online") {
          api.agents().then(setAgents).catch(() => {});
        }
      },
    });
    return close;
  }, [loadRl]);

  // Auto-select first threat if none selected
  const autoSelected = React.useRef(false);
  React.useEffect(() => {
    if (autoSelected.current || selectedId != null || threats.length === 0) return;
    autoSelected.current = true;
    setSelectedId(threats[0].id);
  }, [threats, selectedId]);

  // Load threat detail on selection
  React.useEffect(() => {
    if (selectedId == null) {
      setDetail(null);
      return undefined;
    }
    let alive = true;
    setDetailLoading(true);
    api
      .threat(selectedId)
      .then((d) => alive && setDetail(d))
      .catch((err) => alive && fail(err))
      .finally(() => alive && setDetailLoading(false));
    return () => {
      alive = false;
    };
  }, [selectedId, learned, fail]);

  // ── verdict and policy mutations ───────────────────────────────────────────
  const submitVerdict = async (threatId, action) => {
    setPending(threatId);
    try {
      const result = await api.feedback(threatId, action);
      setThreats((prev) =>
        prev.map((t) => (t.id === threatId ? { ...t, status: result.status } : t)),
      );
      setLearned(result);
      await Promise.all([loadRl(), api.summary().then(setSummary)]);
      setError(null);
    } catch (err) {
      fail(err);
    } finally {
      setPending(null);
    }
  };

  const resetPolicy = async () => {
    try {
      const res = await api.resetPolicy();
      setRl(res.rl);
      setLearned(null);
      await loadRl();
    } catch (err) {
      fail(err);
    }
  };

  const mintToken = async () => {
    try {
      const res = await api.enrollToken();
      return res;
    } catch (err) {
      fail(err);
      return null;
    }
  };

  const handleQuickMint = async () => {
    const t = await mintToken();
    if (t) setQuickToken(t);
  };

  const kem = pqc?.kem?.algorithm || health?.pqc?.kem;
  const openThreatsCount = threats.filter((t) => t.status === "open").length;
  const onlineAgentsCount = agents.filter((a) => a.online).length;

  return (
    <>
      {/* Background Grayscale Ambient Gradients */}
      <div className="bg-gradients" aria-hidden="true" />
      <div className="bg-grid-overlay" aria-hidden="true" />

      <div className="app-shell">
        {/* Left Collapsible Monochrome Sidebar */}
        <Sidebar
          currentRoute={currentRoute}
          onNavigate={setCurrentRoute}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
          conn={conn}
          kem={kem}
          openThreatsCount={openThreatsCount}
          onlineEndpointsCount={onlineAgentsCount}
        />

        {/* Main Viewport */}
        <div className="main-viewport">
          <Header
            currentRoute={currentRoute}
            conn={conn}
            onRefresh={loadAll}
            onMintToken={handleQuickMint}
            refreshing={refreshing}
          />

          {/* Banners */}
          {error && (
            <div style={{ padding: "16px 28px 0" }}>
              <div className="banner error">
                <div>
                  <strong>{error}</strong>
                  <div className="dim" style={{ fontSize: "12px", marginTop: "2px" }}>
                    Ensure the detection server is running on the expected host and port.
                  </div>
                </div>
                <button className="banner-close" onClick={() => setError(null)}>×</button>
              </div>
            </div>
          )}

          {learned && (
            <div style={{ padding: "16px 28px 0" }}>
              <LearnedBanner result={learned} onClose={() => setLearned(null)} />
            </div>
          )}

          {/* Dynamic View Routing */}
          {currentRoute === "dashboard" && (
            <DashboardView
              summary={summary}
              agents={agents}
              threats={threats}
              timeline={timeline}
              scores={scores}
              events={events}
              rl={rl}
              onSelectThreat={setSelectedId}
              onVerdict={submitVerdict}
              pendingVerdict={pending}
              onNavigate={setCurrentRoute}
            />
          )}

          {currentRoute === "threats" && (
            <ThreatsView
              threats={threats}
              selectedId={selectedId}
              onSelectThreat={setSelectedId}
              detail={detail}
              detailLoading={detailLoading}
              onVerdict={submitVerdict}
              pendingVerdict={pending}
            />
          )}

          {currentRoute === "endpoints" && (
            <EndpointsView
              agents={agents}
              onEnrollToken={mintToken}
            />
          )}

          {currentRoute === "analytics" && (
            <AnalyticsView
              timeline={timeline}
              scores={scores}
              qtable={qtable}
              rl={rl}
              threats={threats}
              events={events}
              onResetPolicy={resetPolicy}
            />
          )}

          {currentRoute === "agents" && (
            <AgentsView
              agents={agents}
              onEnrollToken={mintToken}
            />
          )}

          {currentRoute === "policy" && (
            <PolicyCenterView
              onPolicyUpdated={() => loadAll()}
            />
          )}

          {currentRoute === "security" && (
            <SecurityView pqc={pqc} />
          )}

          {currentRoute === "activity" && (
            <ActivityView events={events} />
          )}

          {currentRoute === "settings" && (
            <SettingsView
              model={model}
              health={health}
              rl={rl}
              onResetPolicy={resetPolicy}
            />
          )}
        </div>
      </div>

      {/* Global Quick Mint Modal */}
      <Modal
        isOpen={Boolean(quickToken)}
        onClose={() => setQuickToken(null)}
        title="Agent Enrollment Token"
      >
        <p className="dim" style={{ fontSize: "12.5px" }}>
          Single-use post-quantum token for bootstrapping an endpoint agent.
        </p>

        <div
          style={{
            marginTop: "10px",
            padding: "10px 12px",
            background: "rgba(0,0,0,0.6)",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-sm)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "10px",
          }}
        >
          <span className="mono" style={{ fontSize: "12px", color: "#ffffff", wordBreak: "break-all" }}>
            {quickToken?.token}
          </span>
          <button
            className="btn btn-icon"
            onClick={() => {
              if (quickToken?.token) {
                navigator.clipboard.writeText(quickToken.token);
                setCopiedToken(true);
                setTimeout(() => setCopiedToken(false), 2000);
              }
            }}
            title="Copy"
          >
            {copiedToken ? <Check size={14} color="#ffffff" /> : <Copy size={14} />}
          </button>
        </div>

        <p className="dim" style={{ fontSize: "11.5px", marginTop: "10px" }}>
          Save in <span className="mono">agent_config.yaml</span> as <span className="mono">enroll_token</span>.
        </p>
      </Modal>
    </>
  );
}

function LearnedBanner({ result, onClose }) {
  const l = result.learning || {};
  const parts = [`${l.action} ${fmt(l.reward)}`];
  if (l.endorsed_reward != null) parts.push(`${l.endorsed_action} ${fmt(l.endorsed_reward)}`);

  return (
    <div className="banner learned">
      <div>
        <strong style={{ color: "#ffffff" }}>
          Threat #{result.threat_id} {result.status.toUpperCase()}
        </strong>{" "}
        — policy updated for state <span className="mono">{l.state}</span>: {parts.join(", ")}.
        {result.policy_changed ? (
          <>
            {" "}
            Optimal response transitioned to <strong style={{ color: "#ffffff" }}>{l.policy_after}</strong> (was {l.policy_before}).
          </>
        ) : (
          <> Preserves {l.policy_after} as dominant response.</>
        )}
      </div>
      <button className="banner-close" onClick={onClose} aria-label="Dismiss">
        ×
      </button>
    </div>
  );
}

function fmt(n) {
  const v = Number(n);
  return `${v >= 0 ? "+" : ""}${v.toFixed(1)}`;
}

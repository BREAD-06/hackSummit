import React from "react";

import { ApiError, api, connectLiveFeed } from "./api.js";
import AgentPanel from "./components/AgentPanel.jsx";
import EventFeed from "./components/EventFeed.jsx";
import KpiRow from "./components/KpiRow.jsx";
import PqcPanel from "./components/PqcPanel.jsx";
import QTablePanel from "./components/QTablePanel.jsx";
import ScoreChart from "./components/ScoreChart.jsx";
import ThreatDetail from "./components/ThreatDetail.jsx";
import ThreatTable from "./components/ThreatTable.jsx";
import TimelineChart from "./components/TimelineChart.jsx";
import { SEVERITIES } from "./components/ui.jsx";

const STATUS_TEXT = {
  live: "Live",
  connecting: "Connecting…",
  reconnecting: "Reconnecting…",
  offline: "Server unreachable",
};

/**
 * The SOC dashboard.
 *
 * Threats arrive by WebSocket and are patched into local state rather than
 * refetched, so a burst of activity does not turn into a burst of queries. The
 * slow 20s poll exists for the things a push cannot tell you: that an endpoint
 * went *quiet*. Filtering is entirely client-side for the same reason — a filter
 * that refetched would drop live pushes that don't match it yet.
 */
export default function App() {
  const [theme, setTheme] = React.useState(
    () => localStorage.getItem("vigil-theme") || "dark",
  );
  const [conn, setConn] = React.useState("connecting");
  const [error, setError] = React.useState(null);
  const [learned, setLearned] = React.useState(null);

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

  const [selectedId, setSelectedId] = React.useState(null);
  const [detail, setDetail] = React.useState(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [pending, setPending] = React.useState(null);
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [severityFilter, setSeverityFilter] = React.useState("all");

  React.useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("vigil-theme", theme);
  }, [theme]);

  const fail = React.useCallback((err) => {
    setError(err instanceof ApiError ? err.message : String(err?.message || err));
  }, []);

  // ── loaders ────────────────────────────────────────────────────────────────
  const loadThreatData = React.useCallback(async () => {
    const [t, tl, sc] = await Promise.all([api.threats({ limit: 200 }), api.timeline(), api.scores()]);
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
    }
  }, [loadThreatData, loadRl, loadLive, fail]);

  React.useEffect(() => {
    loadAll();
  }, [loadAll]);

  // Endpoints going quiet is invisible to a push-only feed, so poll for it.
  React.useEffect(() => {
    const id = setInterval(() => {
      loadLive().catch(() => {
        /* the connection dot already reports unreachability */
      });
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
          // The window's hour bucket and its score both changed; both are server-side
          // aggregates, so they have to come from the server.
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

  // ── selection ──────────────────────────────────────────────────────────────
  // Open on the newest threat rather than an empty rail: the detail panel is where
  // a verdict gets justified, so it should already be showing something.
  const autoSelected = React.useRef(false);
  React.useEffect(() => {
    if (autoSelected.current || selectedId != null || threats.length === 0) return;
    autoSelected.current = true;
    setSelectedId(threats[0].id);
  }, [threats, selectedId]);

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
    // Re-fetch when a verdict lands, so "policy now" reflects the update.
  }, [selectedId, learned, fail]);

  // ── the feedback loop ──────────────────────────────────────────────────────
  const submitVerdict = async (threatId, action) => {
    setPending(threatId);
    try {
      const result = await api.feedback(threatId, action);
      // The WebSocket will deliver this too, but a click should feel immediate
      // rather than wait for a round trip through the socket.
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
      return await api.enrollToken();
    } catch (err) {
      fail(err);
      return null;
    }
  };

  // ── derived ────────────────────────────────────────────────────────────────
  const visibleThreats = React.useMemo(() => {
    const floor = SEVERITIES.indexOf(severityFilter);
    return threats.filter((t) => {
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (floor >= 0 && SEVERITIES.indexOf(t.severity) < floor) return false;
      return true;
    });
  }, [threats, statusFilter, severityFilter]);

  const kem = pqc?.kem?.algorithm || health?.pqc?.kem;

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <svg width="26" height="26" viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M12 2 4 5.2v6.4c0 4.7 3.2 9 8 10.4 4.8-1.4 8-5.7 8-10.4V5.2Z"
              fill="none"
              stroke="var(--series-1)"
              strokeWidth="1.8"
            />
            <path d="M8.4 12.1l2.6 2.6 4.6-5.2" fill="none" stroke="var(--series-1)" strokeWidth="1.8" />
          </svg>
          <div>
            <h1>VIGIL AI</h1>
            <p>Insider threat detection · SOC console</p>
          </div>
        </div>

        <span className="badge" title={`WebSocket feed: ${conn}`}>
          <i className={`dot ${conn === "live" ? "live" : conn === "offline" ? "offline" : "connecting"}`} />
          {STATUS_TEXT[conn] || conn}
        </span>

        {kem && (
          <span className="badge" title="Every endpoint batch is encrypted and signed with these">
            PQC <span className="mono">{kem}</span>
          </span>
        )}

        {model && (
          <span className="badge" title={`Trained on ${model.meta?.n_train_windows ?? "?"} windows`}>
            Model <span className="mono">{model.type}</span>
          </span>
        )}

        <button
          className="icon-btn"
          onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        >
          {theme === "dark" ? "Light" : "Dark"} mode
        </button>
        <button className="icon-btn" onClick={loadAll}>
          Refresh
        </button>
      </header>

      {error && (
        <div className="banner error">
          <div>
            <strong>{error}</strong>
            <div className="dim">
              Check that the detection server is running and reachable from this browser.
            </div>
          </div>
          <button onClick={() => setError(null)} aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      {learned && <LearnedBanner result={learned} onClose={() => setLearned(null)} />}

      <KpiRow summary={summary} agents={agents} rl={rl} />

      <div className="stack">
        <div className="grid main">
          <ThreatTable
            threats={visibleThreats}
            selectedId={selectedId}
            onSelect={(id) => setSelectedId(id === selectedId ? null : id)}
            onVerdict={submitVerdict}
            pending={pending}
            statusFilter={statusFilter}
            onStatusFilter={setStatusFilter}
            severityFilter={severityFilter}
            onSeverityFilter={setSeverityFilter}
          />
          <ThreatDetail threat={detail} loading={detailLoading} />
        </div>

        <div className="grid cols-2">
          <TimelineChart timeline={timeline} />
          <ScoreChart scores={scores.scores} threshold={scores.threshold} />
        </div>

        <QTablePanel
          table={qtable}
          stats={rl}
          highlightState={detail?.state}
          onReset={resetPolicy}
        />

        <div className="grid main">
          <EventFeed events={events} />
          <AgentPanel agents={agents} onEnrollToken={mintToken} />
        </div>

        <PqcPanel pqc={pqc} />
      </div>

      <p className="footnote">
        Containment is <strong>simulated</strong>: a BLOCK directive notifies the user and writes a
        local audit record on the endpoint. It never severs the network or kills a process.
      </p>
    </div>
  );
}

/** What one click actually taught the policy — the loop, made legible. */
function LearnedBanner({ result, onClose }) {
  const l = result.learning || {};
  const parts = [`${l.action} ${fmt(l.reward)}`];
  if (l.endorsed_reward != null) parts.push(`${l.endorsed_action} ${fmt(l.endorsed_reward)}`);

  return (
    <div className="banner learned">
      <div>
        <strong>
          Threat #{result.threat_id} {result.status}
        </strong>{" "}
        — policy for <span className="mono">{l.state}</span> updated: {parts.join(", ")}.
        {result.policy_changed ? (
          <>
            {" "}
            It now chooses <strong>{l.policy_after}</strong> here, was {l.policy_before}.
          </>
        ) : (
          <> It still chooses {l.policy_after} here.</>
        )}
      </div>
      <button onClick={onClose} aria-label="Dismiss">
        ×
      </button>
    </div>
  );
}

function fmt(n) {
  const v = Number(n);
  return `${v >= 0 ? "+" : ""}${v.toFixed(1)}`;
}

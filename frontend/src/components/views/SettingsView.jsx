import React from "react";
import {
  Settings,
  Cpu,
  Shield,
  RefreshCw,
  AlertTriangle,
  Server,
  Layers,
  Sliders,
  CheckCircle2,
} from "lucide-react";
import { Card, Chip, Modal } from "../ui.jsx";

export default function SettingsView({
  model,
  health,
  rl,
  onResetPolicy,
}) {
  const [showResetModal, setShowResetModal] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [resetSuccess, setResetSuccess] = React.useState(false);

  const confirmReset = async () => {
    setResetting(true);
    try {
      await onResetPolicy();
      setResetSuccess(true);
      setShowResetModal(false);
      setTimeout(() => setResetSuccess(false), 4000);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="page-content">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
          SOC Console Configuration
        </h1>
        <p className="dim" style={{ fontSize: "13px", marginTop: "2px" }}>
          Manage reinforcement learning decision policies, detection engine thresholds, and telemetry options.
        </p>
      </div>

      {resetSuccess && (
        <div className="banner learned">
          <div>
            <strong>Q-Learning Policy Reset Successful</strong> — Discarded analyst weights and restored rule-based priors.
          </div>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))", gap: "20px" }}>
        {/* Adaptive Response Policy Settings */}
        <Card
          title="Adaptive Response Policy (Q-Learning)"
          hint="Continuous reinforcement learning from SOC analyst dispositions"
          icon={<Cpu size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "13px" }}>
            <p className="dim" style={{ lineHeight: "1.5" }}>
              Every time an analyst blocks a threat or dismisses a false positive, the Q-table updates state action values ($Q(s, a)$) to mirror operational judgment.
            </p>

            <table style={{ background: "transparent" }}>
              <tbody>
                <tr>
                  <td className="dim">State Space</td>
                  <td className="mono">{rl?.n_states ?? 32} discrete behavioral states</td>
                </tr>
                <tr>
                  <td className="dim">States Trained</td>
                  <td className="mono">{rl?.n_states_trained ?? 0} states calibrated</td>
                </tr>
                <tr>
                  <td className="dim">Learning Rate (&alpha;)</td>
                  <td className="mono">{rl?.alpha ?? 0.3}</td>
                </tr>
                <tr>
                  <td className="dim">Discount Factor (&gamma;)</td>
                  <td className="mono">{rl?.gamma ?? 0.8}</td>
                </tr>
              </tbody>
            </table>

            <div style={{ paddingTop: "10px", borderTop: "1px solid var(--border-subtle)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <strong style={{ color: "#ffffff" }}>Revert to Default Rule Prior</strong>
                <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px" }}>
                  Discards learned weights if the policy requires recalibration.
                </p>
              </div>
              <button className="btn" onClick={() => setShowResetModal(true)}>
                Reset Policy
              </button>
            </div>
          </div>
        </Card>

        {/* Isolation Forest ML Detection Engine */}
        <Card
          title="Unsupervised Anomaly Model"
          hint="Machine learning parameters & baseline"
          icon={<Shield size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "13px" }}>
            <p className="dim" style={{ lineHeight: "1.5" }}>
              The Isolation Forest partitions multidimensional telemetry features (file volumes, entropy, timing, sensitive paths) to isolate insider threats without requiring labeled training sets.
            </p>

            <table style={{ background: "transparent" }}>
              <tbody>
                <tr>
                  <td className="dim">Model Architecture</td>
                  <td className="mono" style={{ color: "#ffffff", fontWeight: 600 }}>{model?.type || "Isolation Forest"}</td>
                </tr>
                <tr>
                  <td className="dim">Training Windows</td>
                  <td className="mono">{model?.meta?.n_train_windows ?? "Pre-trained baseline"}</td>
                </tr>
                <tr>
                  <td className="dim">Decision Boundary</td>
                  <td className="mono">Lower score = higher anomaly</td>
                </tr>
                <tr>
                  <td className="dim">Engine Health</td>
                  <td className="mono" style={{ color: "#ffffff" }}>
                    <i className="dot live" style={{ display: "inline-block", marginRight: "6px" }} />
                    {health?.status || "Operational"}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </Card>

        {/* SOC Telemetry Ingestion Parameters */}
        <Card
          title="Telemetry Ingestion & Display"
          hint="Client and daemon synchronization options"
          icon={<Sliders size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "13px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <strong style={{ color: "#ffffff" }}>Active Telemetry Stream</strong>
                <p className="dim" style={{ fontSize: "11.5px" }}>Encrypted WebSocket push via <span className="mono">/api/ws</span></p>
              </div>
              <Chip className="mono">Enabled</Chip>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: "8px", borderTop: "1px solid var(--border-subtle)" }}>
              <div>
                <strong style={{ color: "#ffffff" }}>Liveness Poll Interval</strong>
                <p className="dim" style={{ fontSize: "11.5px" }}>Silent endpoint detection</p>
              </div>
              <span className="mono dim">20 seconds</span>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", paddingTop: "8px", borderTop: "1px solid var(--border-subtle)" }}>
              <div>
                <strong style={{ color: "#ffffff" }}>Queue Buffer Limit</strong>
                <p className="dim" style={{ fontSize: "11.5px" }}>In-memory threat records kept in browser</p>
              </div>
              <span className="mono dim">200 events</span>
            </div>
          </div>
        </Card>

        {/* About VIGIL Platform */}
        <Card
          title="VIGIL AI Enterprise Platform"
          hint="System & Cryptographic Build Info"
          icon={<Server size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "12.5px" }}>
            <p className="dim" style={{ lineHeight: "1.5" }}>
              VIGIL AI provides continuous insider risk intelligence with quantum-resistant key exchange and adaptive reinforcement learning.
            </p>
            <div style={{ padding: "10px", background: "rgba(255,255,255,0.02)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-subtle)", fontSize: "11.5px" }}>
              <span className="mono dim">Server Version: 1.0.0-soc</span><br />
              <span className="mono dim">Post-Quantum: FIPS 203 (ML-KEM-512) + FIPS 204 (ML-DSA-44)</span><br />
              <span className="mono dim">Ingest Origin: {window.location.origin}</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Reset Policy Confirmation Modal */}
      <Modal
        isOpen={showResetModal}
        onClose={() => setShowResetModal(false)}
        title="Confirm Policy Reset"
      >
        <p className="dim" style={{ fontSize: "13px", lineHeight: "1.6" }}>
          Are you sure you want to discard all learned Q-values and revert to the cold-start rule prior?
        </p>
        <p className="dim" style={{ fontSize: "12px", marginTop: "8px" }}>
          All previous analyst endorsements and dismissals will no longer influence the reinforcement learning model's future decisions.
        </p>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "18px" }}>
          <button className="btn" onClick={() => setShowResetModal(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={resetting} onClick={confirmReset}>
            {resetting ? "Resetting..." : "Confirm Reset"}
          </button>
        </div>
      </Modal>
    </div>
  );
}

import React from "react";
import {
  Sliders,
  Shield,
  RotateCcw,
  Check,
  Plus,
  Trash2,
  Folder,
  Tag,
  Save,
  Zap,
} from "lucide-react";
import { Card, Modal } from "../ui.jsx";
import { api, ApiError } from "../../api.js";

const DEFAULT_POLICY = {
  version: 1,
  monitoring: {
    collect_files: true,
    collect_usb: true,
    collect_logon: true,
    watch_dirs: ["Documents", "Downloads", "Desktop"],
    sensitive_keywords: [
      "confidential",
      "secret",
      "password",
      "leak",
      "proprietary",
      "internal",
      "private",
      "salary",
      "patent",
      "financial",
    ],
    sensitive_dirs: [
      "C:\\Confidential",
      "C:\\Finance",
      "C:\\Users\\Public\\Documents",
    ],
  },
  threat_rules: {
    usb_policy: "alert",
    after_hours_policy: "alert",
    file_volume_threshold_mb: 250.0,
    burst_file_count: 100,
    mass_delete_threshold: 20,
    anomaly_sensitivity: "medium",
  },
  response_actions: {
    auto_containment: true,
    max_autonomous_action: "BLOCK",
    containment_mode: "simulated",
  },
};

export default function PolicyCenterView({ onPolicyUpdated }) {
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [resetting, setResetting] = React.useState(false);
  const [showResetModal, setShowResetModal] = React.useState(false);
  const [feedback, setFeedback] = React.useState(null);
  const [error, setError] = React.useState(null);

  const [policy, setPolicy] = React.useState(DEFAULT_POLICY);
  const [newDir, setNewDir] = React.useState("");
  const [newKeyword, setNewKeyword] = React.useState("");
  const [hasChanges, setHasChanges] = React.useState(false);

  const fetchPolicy = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.policy();
      if (data && typeof data === "object") {
        setPolicy({
          ...DEFAULT_POLICY,
          ...data,
          monitoring: { ...DEFAULT_POLICY.monitoring, ...(data.monitoring || {}) },
          threat_rules: { ...DEFAULT_POLICY.threat_rules, ...(data.threat_rules || {}) },
          response_actions: { ...DEFAULT_POLICY.response_actions, ...(data.response_actions || {}) },
        });
      }
      setHasChanges(false);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err?.message || err));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchPolicy();
  }, [fetchPolicy]);

  const updateMonitoring = (key, value) => {
    setPolicy((prev) => ({
      ...prev,
      monitoring: {
        ...(prev.monitoring || DEFAULT_POLICY.monitoring),
        [key]: value,
      },
    }));
    setHasChanges(true);
  };

  const updateThreatRules = (key, value) => {
    setPolicy((prev) => ({
      ...prev,
      threat_rules: {
        ...(prev.threat_rules || DEFAULT_POLICY.threat_rules),
        [key]: value,
      },
    }));
    setHasChanges(true);
  };

  const updateResponseActions = (key, value) => {
    setPolicy((prev) => ({
      ...prev,
      response_actions: {
        ...(prev.response_actions || DEFAULT_POLICY.response_actions),
        [key]: value,
      },
    }));
    setHasChanges(true);
  };

  const addDirectory = (e) => {
    e?.preventDefault();
    const clean = newDir.trim();
    if (!clean) return;
    const current = policy.monitoring?.watch_dirs || [];
    if (!current.includes(clean)) {
      updateMonitoring("watch_dirs", [...current, clean]);
    }
    setNewDir("");
  };

  const removeDirectory = (dirToRemove) => {
    const current = policy.monitoring?.watch_dirs || [];
    updateMonitoring(
      "watch_dirs",
      current.filter((d) => d !== dirToRemove),
    );
  };

  const addKeyword = (e) => {
    e?.preventDefault();
    const clean = newKeyword.trim().toLowerCase();
    if (!clean) return;
    const current = policy.monitoring?.sensitive_keywords || [];
    if (!current.includes(clean)) {
      updateMonitoring("sensitive_keywords", [...current, clean]);
    }
    setNewKeyword("");
  };

  const removeKeyword = (kwToRemove) => {
    const current = policy.monitoring?.sensitive_keywords || [];
    updateMonitoring(
      "sensitive_keywords",
      current.filter((k) => k !== kwToRemove),
    );
  };

  const saveChanges = async () => {
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updatePolicy(policy);
      if (updated) {
        setPolicy({
          ...DEFAULT_POLICY,
          ...updated,
          monitoring: { ...DEFAULT_POLICY.monitoring, ...(updated.monitoring || {}) },
          threat_rules: { ...DEFAULT_POLICY.threat_rules, ...(updated.threat_rules || {}) },
          response_actions: { ...DEFAULT_POLICY.response_actions, ...(updated.response_actions || {}) },
        });
      }
      setHasChanges(false);
      setFeedback({
        title: "Policy Successfully Enforced",
        message:
          "Enterprise detection thresholds, monitoring channels, and automated response rules have been synchronized across active agent nodes.",
      });
      onPolicyUpdated?.(updated);
      setTimeout(() => setFeedback(null), 5000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err?.message || err));
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setResetting(true);
    setError(null);
    try {
      const restored = await api.resetPolicyConfig();
      const p = restored?.policy || restored || DEFAULT_POLICY;
      setPolicy({
        ...DEFAULT_POLICY,
        ...p,
        monitoring: { ...DEFAULT_POLICY.monitoring, ...(p.monitoring || {}) },
        threat_rules: { ...DEFAULT_POLICY.threat_rules, ...(p.threat_rules || {}) },
        response_actions: { ...DEFAULT_POLICY.response_actions, ...(p.response_actions || {}) },
      });
      setHasChanges(false);
      setShowResetModal(false);
      setFeedback({
        title: "Policy Restored to Factory Defaults",
        message: "Default enterprise baseline security rules are now in effect.",
      });
      onPolicyUpdated?.(p);
      setTimeout(() => setFeedback(null), 5000);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err?.message || err));
    } finally {
      setResetting(false);
    }
  };

  const mon = policy.monitoring || DEFAULT_POLICY.monitoring;
  const thr = policy.threat_rules || DEFAULT_POLICY.threat_rules;
  const resp = policy.response_actions || DEFAULT_POLICY.response_actions;

  const watchDirs = Array.isArray(mon.watch_dirs) ? mon.watch_dirs : [];
  const sensitiveKws = Array.isArray(mon.sensitive_keywords) ? mon.sensitive_keywords : [];

  if (loading) {
    return (
      <div className="page-content" style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "60vh" }}>
        <div className="dim mono">Loading enterprise policy configuration...</div>
      </div>
    );
  }

  return (
    <div className="page-content">
      {/* Top Header Bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "16px", flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: "22px", fontWeight: 700, letterSpacing: "-0.02em", color: "#ffffff" }}>
            Enterprise Policy Center
          </h1>
          <p className="dim" style={{ fontSize: "13px", marginTop: "4px" }}>
            Customize endpoint telemetry collection, insider threat qualification thresholds, and autonomous containment directives.
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <button
            className="btn"
            onClick={() => setShowResetModal(true)}
            title="Reset rules to default security baseline"
          >
            <RotateCcw size={14} />
            <span>Restore Defaults</span>
          </button>

          <button
            className="btn btn-primary"
            onClick={saveChanges}
            disabled={saving || !hasChanges}
            title={hasChanges ? "Apply configuration across endpoints" : "No changes to save"}
          >
            {saving ? (
              <span>Deploying...</span>
            ) : (
              <>
                <Save size={14} />
                <span>{hasChanges ? "Deploy Policy" : "Policy Up-to-Date"}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="banner error">
          <div>
            <strong>Policy Configuration Error:</strong> {error}
          </div>
          <button className="banner-close" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {feedback && (
        <div className="banner learned">
          <div>
            <strong style={{ color: "#ffffff" }}>{feedback.title}</strong> — {feedback.message}
          </div>
          <button className="banner-close" onClick={() => setFeedback(null)}>×</button>
        </div>
      )}

      {/* Main Form Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: "20px" }}>
        
        {/* SECTION 1: Monitoring Scope */}
        <Card
          title="Telemetry & Monitoring Scope"
          hint="Control what endpoints inspect and transmit to the SOC"
          icon={<Sliders size={16} />}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "18px", fontSize: "13px" }}>
            {/* Toggles */}
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <label style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", userSelect: "none" }}>
                <div>
                  <strong style={{ color: "#ffffff" }}>File System Operations</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px" }}>
                    Track file creations, modifications, deletions, and mass staging operations.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={Boolean(mon.collect_files)}
                  onChange={(e) => updateMonitoring("collect_files", e.target.checked)}
                  style={{ width: "16px", height: "16px", cursor: "pointer", accentColor: "#ffffff" }}
                />
              </label>

              <label style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", userSelect: "none", paddingTop: "10px", borderTop: "1px solid var(--border-subtle)" }}>
                <div>
                  <strong style={{ color: "#ffffff" }}>Removable Storage & USB Drives</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px" }}>
                    Monitor USB mass storage insertions, drive mountings, and exfiltration volumes.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={Boolean(mon.collect_usb)}
                  onChange={(e) => updateMonitoring("collect_usb", e.target.checked)}
                  style={{ width: "16px", height: "16px", cursor: "pointer", accentColor: "#ffffff" }}
                />
              </label>

              <label style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", userSelect: "none", paddingTop: "10px", borderTop: "1px solid var(--border-subtle)" }}>
                <div>
                  <strong style={{ color: "#ffffff" }}>Authentication & Logon Telemetry</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px" }}>
                    Capture interactive, remote RDP, and after-hours workstation logon events.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={Boolean(mon.collect_logon)}
                  onChange={(e) => updateMonitoring("collect_logon", e.target.checked)}
                  style={{ width: "16px", height: "16px", cursor: "pointer", accentColor: "#ffffff" }}
                />
              </label>
            </div>

            {/* Monitored Directories */}
            <div style={{ paddingTop: "14px", borderTop: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <strong style={{ color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Folder size={14} />
                  Monitored Watch Directories
                </strong>
                <span className="dim" style={{ fontSize: "11px" }}>{watchDirs.length} paths</span>
              </div>
              <p className="dim" style={{ fontSize: "11.5px", marginBottom: "10px" }}>
                Directories designated for high-fidelity integrity observation and canary tripwires.
              </p>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginBottom: "10px" }}>
                {watchDirs.map((dir) => (
                  <div
                    key={dir}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "6px 10px",
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "var(--radius-sm)",
                    }}
                  >
                    <span className="mono" style={{ fontSize: "12px", color: "#ffffff" }}>{dir}</span>
                    <button
                      className="btn-icon"
                      onClick={() => removeDirectory(dir)}
                      title={`Remove ${dir}`}
                      style={{ padding: "3px", color: "var(--muted)" }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>

              <form onSubmit={addDirectory} style={{ display: "flex", gap: "8px" }}>
                <input
                  type="text"
                  placeholder="e.g. C:\TestWatch, C:\Confidential"
                  value={newDir}
                  onChange={(e) => setNewDir(e.target.value)}
                  style={{
                    flex: 1,
                    padding: "7px 10px",
                    fontSize: "12px",
                    background: "rgba(0,0,0,0.5)",
                    border: "1px solid var(--border-medium)",
                    borderRadius: "var(--radius-sm)",
                    color: "#ffffff",
                  }}
                />
                <button type="submit" className="btn" disabled={!newDir.trim()}>
                  <Plus size={13} />
                  <span>Add Path</span>
                </button>
              </form>
            </div>

            {/* Sensitive Keywords */}
            <div style={{ paddingTop: "14px", borderTop: "1px solid var(--border-subtle)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <strong style={{ color: "#ffffff", display: "flex", alignItems: "center", gap: "6px" }}>
                  <Tag size={14} />
                  Sensitive File Keywords
                </strong>
                <span className="dim" style={{ fontSize: "11px" }}>{sensitiveKws.length} tags</span>
              </div>
              <p className="dim" style={{ fontSize: "11.5px", marginBottom: "10px" }}>
                Keywords that trigger instant DLP tripwires and elevate file risk scores.
              </p>

              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "10px" }}>
                {sensitiveKws.map((kw) => (
                  <span
                    key={kw}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "5px",
                      padding: "3px 8px",
                      background: "rgba(255,255,255,0.06)",
                      border: "1px solid var(--border-medium)",
                      borderRadius: "var(--radius-sm)",
                      fontSize: "11.5px",
                      color: "#ffffff",
                    }}
                  >
                    {kw}
                    <button
                      onClick={() => removeKeyword(kw)}
                      style={{ background: "none", border: "none", cursor: "pointer", color: "var(--muted)", padding: 0, display: "flex" }}
                      title={`Remove keyword '${kw}'`}
                    >
                      <Trash2 size={11} />
                    </button>
                  </span>
                ))}
              </div>

              <form onSubmit={addKeyword} style={{ display: "flex", gap: "8px" }}>
                <input
                  type="text"
                  placeholder="e.g. patent, password, leak"
                  value={newKeyword}
                  onChange={(e) => setNewKeyword(e.target.value)}
                  style={{
                    flex: 1,
                    padding: "7px 10px",
                    fontSize: "12px",
                    background: "rgba(0,0,0,0.5)",
                    border: "1px solid var(--border-medium)",
                    borderRadius: "var(--radius-sm)",
                    color: "#ffffff",
                  }}
                />
                <button type="submit" className="btn" disabled={!newKeyword.trim()}>
                  <Plus size={13} />
                  <span>Add Tag</span>
                </button>
              </form>
            </div>
          </div>
        </Card>

        {/* SECTION 2 & 3 */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* SECTION 2: Threat Qualification Criteria */}
          <Card
            title="Threat Qualification Criteria"
            hint="Define behavioral patterns that classify events as active incidents"
            icon={<Shield size={16} />}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: "16px", fontSize: "13px" }}>
              
              {/* USB Policy Selection */}
              <div>
                <strong style={{ color: "#ffffff" }}>Removable Media Enforcement (USB)</strong>
                <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px", marginBottom: "8px" }}>
                  Defines organizational stance on USB mass storage device connections.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  {[
                    { id: "blocked", title: "Strict Block", desc: "Flag as Critical Threat & isolate endpoint" },
                    { id: "alert", title: "Alert Only", desc: "Audit & log alert without immediate host lock" },
                    { id: "allowed", title: "Allowed", desc: "Permitted by company policy" },
                    { id: "disabled", title: "Deactivated", desc: "Do not monitor USB insertions" },
                  ].map((opt) => {
                    const isSelected = (thr.usb_policy || "alert").toLowerCase() === opt.id;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => updateThreatRules("usb_policy", opt.id)}
                        style={{
                          textAlign: "left",
                          padding: "8px 10px",
                          background: isSelected ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.02)",
                          border: `1px solid ${isSelected ? "#ffffff" : "var(--border-subtle)"}`,
                          borderRadius: "var(--radius-sm)",
                          cursor: "pointer",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontWeight: 600, color: "#ffffff", fontSize: "12px" }}>{opt.title}</span>
                          {isSelected && <Check size={12} color="#ffffff" />}
                        </div>
                        <div className="dim" style={{ fontSize: "10.5px", marginTop: "3px" }}>{opt.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* After-Hours Policy */}
              <div style={{ paddingTop: "12px", borderTop: "1px solid var(--border-subtle)" }}>
                <strong style={{ color: "#ffffff" }}>After-Hours Activity (20:00 - 07:00 / Weekends)</strong>
                <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px", marginBottom: "8px" }}>
                  How to classify telemetry generated outside standard working hours.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px" }}>
                  {[
                    { id: "alert", title: "Alert & Correlate", desc: "Elevate threat severity" },
                    { id: "audit", title: "Audit Only", desc: "Record for analytics" },
                    { id: "disabled", title: "Disabled", desc: "Treat as standard hours" },
                  ].map((opt) => {
                    const isSelected = (thr.after_hours_policy || "alert").toLowerCase() === opt.id;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => updateThreatRules("after_hours_policy", opt.id)}
                        style={{
                          textAlign: "left",
                          padding: "8px 10px",
                          background: isSelected ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.02)",
                          border: `1px solid ${isSelected ? "#ffffff" : "var(--border-subtle)"}`,
                          borderRadius: "var(--radius-sm)",
                          cursor: "pointer",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontWeight: 600, color: "#ffffff", fontSize: "12px" }}>{opt.title}</span>
                          {isSelected && <Check size={12} color="#ffffff" />}
                        </div>
                        <div className="dim" style={{ fontSize: "10px", marginTop: "3px" }}>{opt.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Volume Anomaly Threshold & Sensitivity */}
              <div style={{ paddingTop: "12px", borderTop: "1px solid var(--border-subtle)", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                <div>
                  <strong style={{ color: "#ffffff" }}>File Burst Threshold</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px", marginBottom: "6px" }}>
                    File operations before burst staging rule triggers.
                  </p>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <input
                      type="number"
                      min="5"
                      max="1000"
                      value={thr.burst_file_count ?? 100}
                      onChange={(e) => updateThreatRules("burst_file_count", Math.max(1, parseInt(e.target.value) || 100))}
                      style={{
                        width: "100%",
                        padding: "7px 10px",
                        fontSize: "13px",
                        background: "rgba(0,0,0,0.5)",
                        border: "1px solid var(--border-medium)",
                        borderRadius: "var(--radius-sm)",
                        color: "#ffffff",
                      }}
                    />
                    <span className="dim mono" style={{ fontSize: "11px" }}>files</span>
                  </div>
                </div>

                <div>
                  <strong style={{ color: "#ffffff" }}>Isolation Forest Sensitivity</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px", marginBottom: "6px" }}>
                    ML decision boundary stringency.
                  </p>
                  <div style={{ display: "flex", gap: "4px" }}>
                    {[
                      { id: "low", label: "Low", tip: "Strict, fewer alerts" },
                      { id: "medium", label: "Medium", tip: "Balanced default" },
                      { id: "high", label: "High", tip: "Aggressive detection" },
                    ].map((s) => {
                      const isSelected = (thr.anomaly_sensitivity || "medium").toLowerCase() === s.id;
                      return (
                        <button
                          key={s.id}
                          type="button"
                          onClick={() => updateThreatRules("anomaly_sensitivity", s.id)}
                          style={{
                            flex: 1,
                            padding: "6px 4px",
                            fontSize: "11.5px",
                            fontWeight: isSelected ? 700 : 400,
                            background: isSelected ? "#ffffff" : "rgba(255,255,255,0.04)",
                            color: isSelected ? "#000000" : "var(--muted)",
                            border: "1px solid var(--border-medium)",
                            borderRadius: "var(--radius-sm)",
                            cursor: "pointer",
                          }}
                          title={s.tip}
                        >
                          {s.label}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

            </div>
          </Card>

          {/* SECTION 3: Autonomous Response & Containment */}
          <Card
            title="Autonomous Containment & SOAR"
            hint="Establish guardrails for automated endpoint isolation directives"
            icon={<Zap size={16} />}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: "14px", fontSize: "13px" }}>
              <label style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer", userSelect: "none" }}>
                <div>
                  <strong style={{ color: "#ffffff" }}>Automated Host Containment</strong>
                  <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px" }}>
                    When enabled, confirmed high-severity incidents dispatch an immediate cryptographic directive to disconnect the endpoint from network and block USB.
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={Boolean(resp.auto_containment)}
                  onChange={(e) => updateResponseActions("auto_containment", e.target.checked)}
                  style={{ width: "16px", height: "16px", cursor: "pointer", accentColor: "#ffffff" }}
                />
              </label>

              <div style={{ paddingTop: "12px", borderTop: "1px solid var(--border-subtle)" }}>
                <strong style={{ color: "#ffffff" }}>Maximum Autonomous Action Guardrail</strong>
                <p className="dim" style={{ fontSize: "11.5px", marginTop: "2px", marginBottom: "8px" }}>
                  The highest severity action the Q-Learning engine is permitted to execute without human analyst confirmation.
                </p>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px" }}>
                  {[
                    { id: "BLOCK", label: "BLOCK (Max)", desc: "Autonomous endpoint isolation permitted" },
                    { id: "ALERT", label: "ALERT (Mid)", desc: "Flag alerts only; containment requires analyst" },
                    { id: "DISMISS", label: "PASSIVE", desc: "No automated action permitted" },
                  ].map((act) => {
                    const isSelected = (resp.max_autonomous_action || "BLOCK").toUpperCase() === act.id;
                    return (
                      <button
                        key={act.id}
                        type="button"
                        onClick={() => updateResponseActions("max_autonomous_action", act.id)}
                        style={{
                          textAlign: "left",
                          padding: "8px 10px",
                          background: isSelected ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.02)",
                          border: `1px solid ${isSelected ? "#ffffff" : "var(--border-subtle)"}`,
                          borderRadius: "var(--radius-sm)",
                          cursor: "pointer",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontWeight: 600, color: "#ffffff", fontSize: "11.5px" }}>{act.label}</span>
                          {isSelected && <Check size={12} color="#ffffff" />}
                        </div>
                        <div className="dim" style={{ fontSize: "10px", marginTop: "3px" }}>{act.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

            </div>
          </Card>
        </div>

      </div>

      {/* Confirmation Modal for Resetting Policy */}
      <Modal
        isOpen={showResetModal}
        onClose={() => setShowResetModal(false)}
        title="Restore Factory Policy Defaults"
      >
        <p className="dim" style={{ fontSize: "13px", lineHeight: "1.6" }}>
          Are you sure you want to reset all enterprise policy rules to default settings?
        </p>
        <div style={{ margin: "14px 0", padding: "10px", background: "rgba(255,255,255,0.03)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", fontSize: "12px" }}>
          <span className="mono dim">• USB Policy: ALERT</span><br />
          <span className="mono dim">• After-Hours Policy: ALERT</span><br />
          <span className="mono dim">• Burst Threshold: 100 files</span><br />
          <span className="mono dim">• Anomaly Sensitivity: MEDIUM</span><br />
          <span className="mono dim">• Auto Containment: ENABLED (BLOCK)</span>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px", marginTop: "18px" }}>
          <button className="btn" onClick={() => setShowResetModal(false)}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={resetting} onClick={handleReset}>
            {resetting ? "Restoring..." : "Restore Defaults"}
          </button>
        </div>
      </Modal>
    </div>
  );
}

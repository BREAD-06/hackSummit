// Formatting and presentational primitives shared across the VIGIL AI SOC dashboard.
// Strictly monochrome (Black, White, Grayscale only).

import React from "react";
import { AlertCircle, X } from "lucide-react";

export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Bytes in readable units (KB, MB, GB). */
export function bytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = v / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

/** Format numbers with thousands separators. */
export function count(n) {
  const v = Number(n) || 0;
  if (v >= 100000) return `${(v / 1000).toFixed(0)}K`;
  return v.toLocaleString("en-US");
}

export function clockTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleTimeString("en-US", { hour12: false });
}

export function dateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString("en-US", { hour12: false, month: "short", day: "numeric" });
}

/** "3m ago" relative time for agent liveness. */
export function ago(iso) {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "never";
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** Snake_case rules to human words. */
export function humanRule(rule) {
  return String(rule).replace(/_/g, " ");
}

/**
 * Strictly monochrome severity chip.
 * CRITICAL: Inverted pure white background, black bold text, crisp halo.
 * HIGH: Light gray background, dark text.
 * MEDIUM: Charcoal background, white text.
 * LOW: Dark border chip, dim text.
 */
export function SeverityChip({ severity }) {
  const sev = SEVERITIES.includes(severity) ? severity : "LOW";
  return (
    <span className={`chip sev-${sev}`}>
      <i className="swatch" aria-hidden="true" />
      {sev}
    </span>
  );
}

export function Chip({ children, title, className = "" }) {
  return (
    <span className={`chip plain ${className}`} title={title}>
      {children}
    </span>
  );
}

export function Card({ title, hint, actions, icon, children, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-header">
          <div className="card-title-group">
            {title && (
              <h2 className="card-title">
                {icon && <span style={{ display: "inline-flex", color: "var(--muted)" }}>{icon}</span>}
                {title}
              </h2>
            )}
            {hint && <p className="card-hint">{hint}</p>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Empty({ children, message }) {
  return (
    <div className="empty-state">
      <div className="empty-state-icon">
        <AlertCircle size={20} />
      </div>
      <p className="empty-state-text">{message || children || "No data available."}</p>
    </div>
  );
}

export function Modal({ isOpen, onClose, title, children }) {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">{title}</h3>
          <button className="btn-icon" onClick={onClose} aria-label="Close dialog">
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

/** Tracks the pixel width of an element, so SVG charts can be responsive. */
export function useWidth(ref, fallback = 640) {
  const [width, setWidth] = React.useState(fallback);
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const ro = new ResizeObserver(([entry]) => {
      const w = entry.contentRect.width;
      if (w > 0) setWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return width;
}

// Formatting and tiny presentational primitives shared by every panel.

import React from "react";

export const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Bytes in the units an analyst actually reads. */
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

/** Thousands separators, and compact only past 5 digits so counts stay exact. */
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

/** "3m ago" — the form that matters for an agent-liveness column. */
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

/** Rule keys are snake_case on the wire; show them as words. */
export function humanRule(rule) {
  return String(rule).replace(/_/g, " ");
}

/**
 * Severity always renders as a named chip, never as bare color.
 *
 * The amber/orange pair (MEDIUM/HIGH) sits below the normal-vision separation
 * floor, so the word is the datum and the swatch is only a fast second read.
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

export function Chip({ children, title }) {
  return (
    <span className="chip plain" title={title}>
      {children}
    </span>
  );
}

export function Card({ title, hint, actions, children, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header>
          {title && <h2>{title}</h2>}
          {hint && <p className="hint">{hint}</p>}
          {actions && <div className="spacer">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ children }) {
  return <p className="empty-state">{children}</p>;
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

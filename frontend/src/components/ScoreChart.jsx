import React from "react";

import { Card, count, useWidth } from "./ui.jsx";

const MAX_BINS = 22;

/** Bins scaled to the sample: 22 bins over 3 scores is noise, not a distribution. */
function binCount(n) {
  if (n <= 1) return 1;
  return Math.max(4, Math.min(MAX_BINS, Math.ceil(Math.sqrt(n))));
}

/**
 * Distribution of Isolation Forest scores, with the model's decision threshold
 * drawn on it.
 *
 * Reading the model matters as much as reading the alerts: the threshold line
 * shows *where* the boundary sits, and the shape of the histogram shows whether
 * the flagged windows are genuine outliers in a long tail or a smear across the
 * middle. Higher score = more normal, so anomalies are the bars to the LEFT of
 * the line — stated in the caption, because that is the opposite of what most
 * people assume.
 *
 * One series, so no legend; the threshold gets a direct label instead.
 */
export default function ScoreChart({ scores, threshold }) {
  const box = React.useRef(null);
  const width = useWidth(box, 640);
  const [hover, setHover] = React.useState(null);
  const [view, setView] = React.useState("chart");

  const values = React.useMemo(
    () =>
      (scores || [])
        .map((s) => Number(s.anomaly_score))
        .filter((v) => Number.isFinite(v)),
    [scores],
  );

  const stats = React.useMemo(() => {
    if (!values.length) return null;
    const lo = Math.min(...values, Number(threshold) || 0);
    const hi = Math.max(...values, Number(threshold) || 0);
    // A degenerate range (every score identical) would divide by zero; pad it.
    const span = hi - lo || 1;
    const min = lo - span * 0.04;
    const max = hi + span * 0.04;
    const nBins = binCount(values.length);
    const w = (max - min) / nBins;

    const bins = Array.from({ length: nBins }, (_, i) => ({
      i,
      from: min + i * w,
      to: min + (i + 1) * w,
      n: 0,
    }));
    for (const v of values) {
      const idx = Math.min(nBins - 1, Math.max(0, Math.floor((v - min) / w)));
      bins[idx].n += 1;
    }
    return { min, max, bins, nBins, peak: Math.max(1, ...bins.map((b) => b.n)) };
  }, [values, threshold]);

  const PAD = { top: 10, right: 8, bottom: 22, left: 30 };
  const plotW = Math.max(120, width - PAD.left - PAD.right);
  const plotH = 118;
  const height = plotH + PAD.top + PAD.bottom;

  if (!stats) {
    return (
      <Card title="Anomaly score distribution">
        <p className="empty-state">No scored windows yet.</p>
      </Card>
    );
  }

  const { min, max, bins, nBins, peak } = stats;
  const sx = (v) => PAD.left + ((v - min) / (max - min)) * plotW;
  const sy = (n) => PAD.top + plotH - (n / peak) * plotH;
  const binW = plotW / nBins;
  // Capped and centred: with a handful of scores the bins are enormous, and a
  // 100px-wide bar reads as a filled region rather than a count.
  const barW = Math.max(2, Math.min(30, binW - 2));
  const barX = (i) => PAD.left + i * binW + (binW - barW) / 2;

  const thr = Number(threshold);
  const hasThreshold = Number.isFinite(thr);
  const anomalies = hasThreshold ? values.filter((v) => v < thr).length : 0;

  const step = Math.max(1, Math.ceil(peak / 3));
  const ticks = [];
  for (let t = 0; t <= peak; t += step) ticks.push(t);

  return (
    <Card
      title="Anomaly score distribution"
      hint={`${count(values.length)} window${values.length === 1 ? "" : "s"} · ${
        hasThreshold ? `${anomalies} below threshold` : "no threshold"
      }`}
      actions={
        <div className="tabs" role="tablist" aria-label="Distribution view">
          {["chart", "table"].map((v) => (
            <button
              key={v}
              className="tab"
              role="tab"
              aria-selected={view === v}
              onClick={() => setView(v)}
            >
              {v === "chart" ? "Chart" : "Table"}
            </button>
          ))}
        </div>
      }
    >
      {view === "table" ? (
        <div className="table-wrap" style={{ maxHeight: 210, overflowY: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>Score range</th>
                <th className="num">Windows</th>
              </tr>
            </thead>
            <tbody>
              {bins
                .filter((b) => b.n > 0)
                .map((b) => (
                  <tr key={b.i}>
                    <td className="mono">
                      {b.from.toFixed(3)} … {b.to.toFixed(3)}
                    </td>
                    <td className="num">{b.n}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart" ref={box} onMouseLeave={() => setHover(null)}>
          <svg
            height={height}
            viewBox={`0 0 ${Math.max(width, 1)} ${height}`}
            role="img"
            aria-label={`Histogram of ${values.length} anomaly scores. ${
              hasThreshold ? `${anomalies} fall below the decision threshold.` : ""
            }`}
          >
            {ticks.map((t) => (
              <g key={t}>
                <line className="gridline" x1={PAD.left} y1={sy(t)} x2={width - PAD.right} y2={sy(t)} />
                <text className="axis-label" x={PAD.left - 7} y={sy(t) + 3} textAnchor="end">
                  {t}
                </text>
              </g>
            ))}
            <line className="baseline" x1={PAD.left} y1={sy(0)} x2={width - PAD.right} y2={sy(0)} />

            {bins.map((b) => {
              if (b.n === 0) return null;
              const h = Math.max(3, (b.n / peak) * plotH);
              return (
                <rect
                  key={b.i}
                  className="bar"
                  x={barX(b.i)}
                  y={PAD.top + plotH - h}
                  width={barW}
                  height={h}
                  rx={Math.min(4, barW / 2)}
                />
              );
            })}

            {/* Hover band per bin, full plot height — bigger than the mark. */}
            {bins.map((b) => (
              <rect
                key={`hit-${b.i}`}
                x={PAD.left + b.i * binW}
                y={PAD.top}
                width={binW}
                height={plotH}
                fill="transparent"
                onMouseEnter={() =>
                  setHover({ ...b, cx: PAD.left + b.i * binW + binW / 2 })
                }
              />
            ))}

            {hasThreshold && (
              <>
                <line className="threshold" x1={sx(thr)} y1={PAD.top - 4} x2={sx(thr)} y2={sy(0)} />
                <text
                  className="axis-label"
                  x={Math.min(sx(thr) + 5, width - PAD.right - 52)}
                  y={PAD.top + 4}
                >
                  threshold
                </text>
              </>
            )}

            <text className="axis-label" x={PAD.left} y={height - 5}>
              {min.toFixed(2)} (anomalous)
            </text>
            <text className="axis-label" x={width - PAD.right} y={height - 5} textAnchor="end">
              {max.toFixed(2)} (normal)
            </text>
          </svg>

          {hover && (
            <div className="tooltip" style={{ left: hover.cx, top: PAD.top - 2 }}>
              {hover.from.toFixed(3)} … {hover.to.toFixed(3)} — {hover.n} window
              {hover.n === 1 ? "" : "s"}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

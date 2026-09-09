import React from "react";

import { Card, count, useWidth } from "./ui.jsx";

/**
 * Threats per hour of the day, as columns.
 *
 * One series, so no legend — the title says what is plotted. Values come from the
 * hover tooltip and the table view rather than a label on all 24 columns, which
 * would be unreadable. Geometry is in real pixels (measured, not a stretched
 * viewBox) so the rounded bar ends and hairlines stay undistorted at any width.
 */
export default function TimelineChart({ timeline }) {
  const box = React.useRef(null);
  const width = useWidth(box, 640);
  const [hover, setHover] = React.useState(null);
  const [view, setView] = React.useState("chart");

  const buckets = React.useMemo(
    () =>
      Array.from({ length: 24 }, (_, hour) => {
        const found = (timeline || []).find((t) => Number(t.hour) === hour);
        return { hour, count: Number(found?.count) || 0 };
      }),
    [timeline],
  );

  const total = buckets.reduce((sum, b) => sum + b.count, 0);
  const peak = Math.max(1, ...buckets.map((b) => b.count));
  const busiest = buckets.reduce((a, b) => (b.count > a.count ? b : a), buckets[0]);

  // Height includes the x-axis band, so the card never grows an inner scrollbar
  // just to reveal its own tick labels.
  const PAD = { top: 8, right: 4, bottom: 20, left: 30 };
  const plotW = Math.max(120, width - PAD.left - PAD.right);
  const plotH = 118;
  const height = plotH + PAD.top + PAD.bottom;

  const slot = plotW / 24;
  const barW = Math.min(24, slot * 0.56); // capped; the band's leftover is air
  const x = (hour) => PAD.left + hour * slot + (slot - barW) / 2;
  const y = (value) => PAD.top + plotH - (value / peak) * plotH;

  // Clean tick numbers rather than thirds of an arbitrary peak.
  const step = Math.max(1, Math.ceil(peak / 3));
  const ticks = [];
  for (let t = 0; t <= peak; t += step) ticks.push(t);

  return (
    <Card
      title="Threat activity by hour"
      hint={total ? `${count(total)} threat window${total === 1 ? "" : "s"}` : null}
      actions={
        <div className="tabs" role="tablist" aria-label="Timeline view">
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
                <th>Hour</th>
                <th className="num">Threat windows</th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((b) => (
                <tr key={b.hour}>
                  <td className="mono">{String(b.hour).padStart(2, "0")}:00</td>
                  <td className="num">{b.count}</td>
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
            aria-label={
              total
                ? `Threats per hour of day. Peak ${peak} at ${busiest.hour}:00.`
                : "Threats per hour of day. No threats recorded yet."
            }
          >
            {ticks.map((t) => (
              <g key={t}>
                <line className="gridline" x1={PAD.left} y1={y(t)} x2={width - PAD.right} y2={y(t)} />
                <text className="axis-label" x={PAD.left - 7} y={y(t) + 3} textAnchor="end">
                  {t}
                </text>
              </g>
            ))}
            <line className="baseline" x1={PAD.left} y1={y(0)} x2={width - PAD.right} y2={y(0)} />

            {buckets.map((b) => {
              // An empty hour keeps a 2px stub in the gridline gray: the axis stays
              // legible as a 24-slot day instead of collapsing to a few bars.
              const h = b.count === 0 ? 2 : Math.max(3, (b.count / peak) * plotH);
              return (
                <g key={b.hour}>
                  <rect
                    className={`bar ${b.count === 0 ? "empty" : ""}`}
                    x={x(b.hour)}
                    y={PAD.top + plotH - h}
                    width={barW}
                    height={h}
                    rx={Math.min(4, barW / 2)}
                  />
                  {/* Hit target spans the whole slot and the full plot height, so
                      hovering a 2px stub does not require pixel precision. */}
                  <rect
                    x={PAD.left + b.hour * slot}
                    y={PAD.top}
                    width={slot}
                    height={plotH}
                    fill="transparent"
                    onMouseEnter={() =>
                      setHover({ ...b, cx: PAD.left + b.hour * slot + slot / 2 })
                    }
                  />
                </g>
              );
            })}

            {[0, 6, 12, 18, 23].map((hour) => (
              <text
                key={hour}
                className="axis-label"
                x={PAD.left + hour * slot + slot / 2}
                y={height - 6}
                textAnchor="middle"
              >
                {String(hour).padStart(2, "0")}
              </text>
            ))}
          </svg>

          {hover && (
            <div className="tooltip" style={{ left: hover.cx, top: PAD.top - 2 }}>
              {String(hover.hour).padStart(2, "0")}:00 — {hover.count} threat
              {hover.count === 1 ? "" : "s"}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

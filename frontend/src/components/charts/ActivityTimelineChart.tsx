import { useEffect, useRef, useState } from "react";
import type { ActivityBucket } from "./types";

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}

export default function ActivityTimelineChart({
  buckets,
  theme,
}: {
  buckets: ActivityBucket[];
  theme: "dark" | "light";
}) {
  const chartRef = useRef<HTMLDivElement | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltip, setTooltip] = useState<{
    x: number;
    y: number;
    width: number;
  } | null>(null);

  useEffect(() => {
    const target = chartRef.current;
    if (!target) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.28, rootMargin: "0px 0px -40px 0px" },
    );

    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  if (buckets.length === 0) {
    return (
      <div className="rounded-3xl border border-white/10 bg-slate-950/45 p-6 text-sm text-slate-400">
        No timestamped activity was detected for plotting.
      </div>
    );
  }

  const chartWidth = 780;
  const chartHeight = 260;
  const leftPad = 54;
  const rightPad = 24;
  const topPad = 20;
  const bottomPad = 52;
  const innerWidth = chartWidth - leftPad - rightPad;
  const innerHeight = chartHeight - topPad - bottomPad;
  const maxCount = Math.max(...buckets.map((entry) => entry.count), 1);

  const pointCoords = buckets.map((entry, index) => {
    const x =
      leftPad +
      (index / Math.max(buckets.length - 1, 1)) * Math.max(innerWidth, 1);
    const y =
      topPad +
      innerHeight -
      (entry.count / maxCount) * Math.max(innerHeight, 1);
    return { x, y, count: entry.count, timeLabel: entry.timeLabel };
  });

  const points = pointCoords.map((point) => `${point.x},${point.y}`).join(" ");

  const areaPath =
    pointCoords.length > 0
      ? `M ${pointCoords[0]?.x} ${topPad + innerHeight} L ${pointCoords
          .map((point) => `${point.x} ${point.y}`)
          .join(
            " L ",
          )} L ${pointCoords[pointCoords.length - 1]?.x} ${topPad + innerHeight} Z`
      : "";

  const polylineLength = pointCoords.reduce((total, point, index) => {
    if (index === 0) return total;
    const prev = pointCoords[index - 1];
    return total + Math.hypot(point.x - prev.x, point.y - prev.y);
  }, 0);

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {
    const y = topPad + innerHeight - ratio * innerHeight;
    const value = Math.round(ratio * maxCount);
    return { y, value };
  });

  const axisStroke =
    theme === "light" ? "rgba(71, 85, 105, 0.55)" : "rgba(148, 163, 184, 0.45)";
  const gridStroke =
    theme === "light"
      ? "rgba(100, 116, 139, 0.35)"
      : "rgba(148, 163, 184, 0.25)";
  const axisLabelColor =
    theme === "light" ? "rgba(30, 41, 59, 0.92)" : "rgba(148, 163, 184, 0.95)";
  const tickLabelColor =
    theme === "light" ? "rgba(15, 23, 42, 0.88)" : "rgba(203, 213, 225, 0.9)";

  return (
    <div
      ref={chartRef}
      className="relative rounded-3xl border border-white/10 bg-slate-950/45 p-4 sm:p-5"
    >
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
        X axis: time | Y axis: number of activities
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight}`}
          className="min-w-[560px] w-full"
          role="img"
          aria-label="Activity timeline graph"
        >
          {yTicks.map((tick) => (
            <g key={`tick-${tick.y}`}>
              <line
                x1={leftPad}
                y1={tick.y}
                x2={chartWidth - rightPad}
                y2={tick.y}
                stroke={gridStroke}
                strokeDasharray="4 4"
              />
              <text
                x={leftPad - 10}
                y={tick.y + 4}
                textAnchor="end"
                fontSize="11"
                fill={tickLabelColor}
              >
                {tick.value}
              </text>
            </g>
          ))}

          <line
            x1={leftPad}
            y1={topPad + innerHeight}
            x2={chartWidth - rightPad}
            y2={topPad + innerHeight}
            stroke={axisStroke}
          />

          <line
            x1={leftPad}
            y1={topPad}
            x2={leftPad}
            y2={topPad + innerHeight}
            stroke={axisStroke}
          />

          {areaPath ? (
            <path
              d={areaPath}
              fill="url(#timeline-fill-gradient)"
              className={`timeline-area-fill ${isVisible ? "timeline-area-fill--visible" : ""}`}
            />
          ) : null}

          <polyline
            points={points}
            fill="none"
            stroke="rgba(34, 211, 238, 0.95)"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            style={{
              strokeDasharray: polylineLength,
              strokeDashoffset: isVisible ? 0 : polylineLength,
              transition:
                "stroke-dashoffset 1200ms cubic-bezier(0.2, 0.78, 0.2, 1)",
            }}
          />

          {pointCoords.map((entry, index) => {
            const isActive = hoveredIndex === index;
            return (
              <g key={`${entry.timeLabel}-${index}`}>
                <circle
                  cx={entry.x}
                  cy={entry.y}
                  r="11"
                  fill="transparent"
                  onPointerEnter={(event) => {
                    const svg = event.currentTarget.ownerSVGElement;
                    if (!svg) return;
                    const rect = svg.getBoundingClientRect();
                    setHoveredIndex(index);
                    setTooltip({
                      x: event.clientX - rect.left,
                      y: event.clientY - rect.top,
                      width: rect.width,
                    });
                  }}
                  onPointerMove={(event) => {
                    const svg = event.currentTarget.ownerSVGElement;
                    if (!svg) return;
                    const rect = svg.getBoundingClientRect();
                    setTooltip({
                      x: event.clientX - rect.left,
                      y: event.clientY - rect.top,
                      width: rect.width,
                    });
                  }}
                  onPointerLeave={() => {
                    setHoveredIndex(null);
                    setTooltip(null);
                  }}
                  style={{ cursor: "pointer" }}
                />
                <circle
                  cx={entry.x}
                  cy={entry.y}
                  r={isActive ? 6.2 : 4.2}
                  fill="rgba(34, 211, 238, 1)"
                  className="timeline-point"
                  style={{
                    transition:
                      "r 220ms ease, filter 220ms ease, opacity 260ms ease",
                    filter: isActive
                      ? "drop-shadow(0 0 9px rgba(56, 189, 248, 0.95))"
                      : "none",
                    opacity: isVisible ? 1 : 0,
                    transitionDelay: `${120 + index * 60}ms`,
                  }}
                />
                <text
                  x={entry.x}
                  y={chartHeight - 16}
                  textAnchor="middle"
                  fontSize="10"
                  fill={
                    isActive
                      ? theme === "light"
                        ? "#0f172a"
                        : "#f8fafc"
                      : theme === "light"
                        ? "rgba(30, 41, 59, 0.9)"
                        : "rgba(203, 213, 225, 0.92)"
                  }
                  style={{ transition: "fill 180ms ease" }}
                >
                  {entry.timeLabel}
                </text>
              </g>
            );
          })}

          <text
            x={leftPad + innerWidth / 2}
            y={chartHeight - 2}
            textAnchor="middle"
            fontSize="11"
            fill={axisLabelColor}
          >
            Time
          </text>
          <text
            x={16}
            y={topPad + innerHeight / 2}
            textAnchor="middle"
            fontSize="11"
            fill={axisLabelColor}
            transform={`rotate(-90 16 ${topPad + innerHeight / 2})`}
          >
            Number of Activities
          </text>

          <defs>
            <linearGradient
              id="timeline-fill-gradient"
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop offset="0%" stopColor="rgba(56,189,248,0.28)" />
              <stop offset="100%" stopColor="rgba(56,189,248,0.02)" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      {hoveredIndex !== null && tooltip ? (
        <div
          className={`pointer-events-none absolute z-20 rounded-xl px-3 py-2 text-xs shadow-xl ${
            theme === "light"
              ? "border border-slate-300/80 bg-white/95 text-slate-800"
              : "border border-cyan-400/30 bg-slate-950/95 text-cyan-50"
          }`}
          style={{
            left: `${Math.min(tooltip.x + 14, Math.max(tooltip.width - 176, 12))}px`,
            top: `${Math.max(tooltip.y - 18, 12)}px`,
          }}
        >
          <p className="font-semibold">
            {pointCoords[hoveredIndex]?.timeLabel}
          </p>
          <p>
            Activities: {formatNumber(pointCoords[hoveredIndex]?.count ?? 0)}
          </p>
        </div>
      ) : null}
    </div>
  );
}

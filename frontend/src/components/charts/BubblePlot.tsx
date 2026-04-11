import { type PointerEvent, useEffect, useRef, useState } from "react";
import { bubblePalette, type BubbleGroup, type BubblePoint } from "./types";

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}

export default function BubblePlot({
  points,
  theme,
}: {
  points: BubblePoint[];
  theme: "dark" | "light";
}) {
  const bubbleRef = useRef<HTMLDivElement | null>(null);
  const [activeGroup, setActiveGroup] = useState<BubbleGroup | "All">("All");
  const [activePointId, setActivePointId] = useState<string | null>(null);
  const [isVisible, setIsVisible] = useState(false);
  const [tooltip, setTooltip] = useState<{
    id: string;
    x: number;
    y: number;
    width: number;
  } | null>(null);

  useEffect(() => {
    const target = bubbleRef.current;
    if (!target) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.24, rootMargin: "0px 0px -24px 0px" },
    );

    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  if (points.length === 0) {
    return (
      <div className="rounded-3xl border border-white/10 bg-slate-950/45 p-6 text-sm text-slate-400">
        No threat-actor data available for the bubble plot yet.
      </div>
    );
  }

  const width = 860;
  const height = 420;
  const leftPad = 72;
  const rightPad = 176;
  const topPad = 24;
  const bottomPad = 56;
  const innerWidth = width - leftPad - rightPad;
  const innerHeight = height - topPad - bottomPad;

  const xMax = Math.max(...points.map((point) => point.xValue), 1);
  const yMax = Math.max(...points.map((point) => point.yValue), 1);
  const minRawSize = Math.min(...points.map((point) => point.sizeValue));
  const maxRawSize = Math.max(...points.map((point) => point.sizeValue));

  const radiusFor = (value: number) => {
    if (maxRawSize === minRawSize) return 14;
    const normalized = (value - minRawSize) / (maxRawSize - minRawSize);
    return 8 + Math.sqrt(Math.max(normalized, 0)) * 18;
  };

  const plotted = points.map((point) => {
    const radius = radiusFor(point.sizeValue);
    const rawCx = leftPad + (point.xValue / xMax) * innerWidth;
    const rawCy = topPad + innerHeight - (point.yValue / yMax) * innerHeight;
    const cx = Math.min(
      leftPad + innerWidth - radius,
      Math.max(leftPad + radius, rawCx),
    );
    const cy = Math.min(
      topPad + innerHeight - radius,
      Math.max(topPad + radius, rawCy),
    );
    return { ...point, cx, cy, radius };
  });

  const activePoint =
    plotted.find((point) => point.id === activePointId) ?? null;
  const groups = Object.keys(bubblePalette) as BubbleGroup[];
  const axisStroke =
    theme === "light" ? "rgba(71, 85, 105, 0.55)" : "rgba(148,163,184,0.5)";
  const gridYStroke =
    theme === "light" ? "rgba(100,116,139,0.34)" : "rgba(148,163,184,0.22)";
  const gridXStroke =
    theme === "light" ? "rgba(100,116,139,0.22)" : "rgba(148,163,184,0.14)";
  const axisLabel =
    theme === "light" ? "rgba(30,41,59,0.92)" : "rgba(148,163,184,0.95)";
  const tickLabel =
    theme === "light" ? "rgba(15,23,42,0.9)" : "rgba(203,213,225,0.9)";

  function handlePointMove(
    event: PointerEvent<SVGCircleElement>,
    pointId: string,
  ) {
    const svg = event.currentTarget.ownerSVGElement;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    setTooltip({
      id: pointId,
      x: event.clientX - rect.left,
      y: event.clientY - rect.top,
      width: rect.width,
    });
    setActivePointId(pointId);
  }

  function clearPointHover() {
    setActivePointId(null);
    setTooltip(null);
  }

  return (
    <div
      ref={bubbleRef}
      className="relative rounded-3xl border border-white/10 bg-slate-950/45 p-4 sm:p-5"
    >
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
        X axis: activity pressure | Y axis: threat complexity | Bubble size:
        actor volume
      </div>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="min-w-[620px] w-full"
          role="img"
          aria-label="Threat bubble plot"
        >
          <defs>
            <clipPath id="bubble-plot-clip">
              <rect
                x={leftPad}
                y={topPad}
                width={innerWidth}
                height={innerHeight}
              />
            </clipPath>
          </defs>

          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = topPad + innerHeight - ratio * innerHeight;
            const label = Math.round(yMax * ratio);
            return (
              <g key={`y-${ratio}`}>
                <line
                  x1={leftPad}
                  y1={y}
                  x2={leftPad + innerWidth}
                  y2={y}
                  stroke={gridYStroke}
                  strokeDasharray="3 5"
                />
                <text
                  x={leftPad - 10}
                  y={y + 4}
                  textAnchor="end"
                  fontSize="11"
                  fill={tickLabel}
                >
                  {label}
                </text>
              </g>
            );
          })}

          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const x = leftPad + ratio * innerWidth;
            const label = Math.round(xMax * ratio);
            return (
              <g key={`x-${ratio}`}>
                <line
                  x1={x}
                  y1={topPad}
                  x2={x}
                  y2={topPad + innerHeight}
                  stroke={gridXStroke}
                />
                <text
                  x={x}
                  y={height - 20}
                  textAnchor="middle"
                  fontSize="11"
                  fill={tickLabel}
                >
                  {label}
                </text>
              </g>
            );
          })}

          <line
            x1={leftPad}
            y1={topPad + innerHeight}
            x2={leftPad + innerWidth}
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

          <g clipPath="url(#bubble-plot-clip)">
            {plotted.map((point) => {
              const isDimmed =
                activeGroup !== "All" && point.group !== activeGroup;
              const isActive = point.id === activePointId;
              return (
                <g key={point.id}>
                  <circle
                    cx={point.cx}
                    cy={point.cy}
                    r={Math.max(point.radius, 14)}
                    fill="transparent"
                    onPointerEnter={(event) => handlePointMove(event, point.id)}
                    onPointerMove={(event) => handlePointMove(event, point.id)}
                    onPointerLeave={clearPointHover}
                    style={{ cursor: "pointer" }}
                  />
                  <circle
                    cx={point.cx}
                    cy={point.cy}
                    r={point.radius}
                    fill={bubblePalette[point.group]}
                    fillOpacity={isDimmed ? 0.16 : 0.36}
                    stroke={bubblePalette[point.group]}
                    strokeWidth={isActive ? 2.8 : 1.2}
                    className={`bubble-point ${isVisible ? "bubble-point--visible" : ""}`}
                    style={{
                      transitionDelay: `${90 + (Number(point.id.replace(/\D/g, "")) % 8) * 40}ms`,
                      filter: isActive
                        ? "drop-shadow(0 0 16px rgba(255,255,255,0.3))"
                        : "none",
                      transformBox: "fill-box",
                      transformOrigin: "center",
                    }}
                    pointerEvents="none"
                  />
                </g>
              );
            })}
          </g>

          <text
            x={leftPad + innerWidth / 2}
            y={height - 2}
            textAnchor="middle"
            fontSize="12"
            fill={axisLabel}
          >
            Activity pressure score
          </text>

          <text
            x={24}
            y={topPad + innerHeight / 2}
            textAnchor="middle"
            fontSize="12"
            fill={axisLabel}
            transform={`rotate(-90 24 ${topPad + innerHeight / 2})`}
          >
            Threat complexity score
          </text>

          <text
            x={leftPad + innerWidth + 18}
            y={topPad + 12}
            fontSize="11"
            fill={axisLabel}
          >
            Groups
          </text>
          {groups.map((group, index) => {
            const y = topPad + 34 + index * 24;
            return (
              <g
                key={group}
                onMouseEnter={() => setActiveGroup(group)}
                onMouseLeave={() => setActiveGroup("All")}
              >
                <circle
                  cx={leftPad + innerWidth + 18}
                  cy={y - 5}
                  r="6"
                  fill={bubblePalette[group]}
                />
                <text
                  x={leftPad + innerWidth + 30}
                  y={y - 2}
                  fontSize="12"
                  fill={
                    activeGroup === group
                      ? theme === "light"
                        ? "#020617"
                        : "#ffffff"
                      : tickLabel
                  }
                >
                  {group}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {tooltip && activePoint && tooltip.id === activePoint.id ? (
        <div
          className={`pointer-events-none absolute z-20 rounded-xl px-3 py-2 text-xs shadow-xl ${
            theme === "light"
              ? "border border-slate-300/80 bg-white/95 text-slate-800"
              : "border border-cyan-400/30 bg-slate-950/95 text-cyan-50"
          }`}
          style={{
            left: `${Math.min(tooltip.x + 14, Math.max(tooltip.width - 220, 12))}px`,
            top: `${Math.max(tooltip.y - 22, 12)}px`,
          }}
        >
          <p className="font-semibold">{activePoint.label}</p>
          <p>Hits: {formatNumber(activePoint.hits)}</p>
          <p>Failures: {formatNumber(activePoint.failures)}</p>
        </div>
      ) : null}

      {activePoint ? (
        <div className="mt-3 rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          <span className="font-semibold text-white">{activePoint.label}</span>{" "}
          | Hits: {formatNumber(activePoint.hits)} | Failed attempts:{" "}
          {formatNumber(activePoint.failures)} | Tags:{" "}
          {activePoint.tags.slice(0, 4).join(", ") || "None"}
        </div>
      ) : null}
    </div>
  );
}

import { ChangeEvent, type ReactNode, useEffect, useState } from "react";
import type { ForensicReport, GapEntry, ThreatActor } from "./types";

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://127.0.0.1:5000";

function buildUrl(path: string) {
  return `${API_BASE}${path}`;
}

function isNetworkError(error: unknown) {
  return error instanceof TypeError;
}

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}

function formatBytes(value?: number) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatDate(value?: string) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatDuration(seconds?: number) {
  if (seconds === undefined || Number.isNaN(seconds)) return "—";
  const absolute = Math.abs(Math.trunc(seconds));
  if (absolute < 60) return `${absolute}s`;
  if (absolute < 3600) {
    const minutes = Math.floor(absolute / 60);
    const remaining = absolute % 60;
    return `${minutes}m ${remaining}s`;
  }
  const hours = Math.floor(absolute / 3600);
  const remainingMinutes = Math.floor((absolute % 3600) / 60);
  return `${hours}h ${remainingMinutes}m`;
}

function calculateRisk(report?: ForensicReport) {
  if (!report) return 0;

  const gaps = report.gaps ?? [];
  const threats = report.threats ?? [];

  if (gaps.length === 0 && threats.length === 0) return 0;

  const zoneProbs = {
    integrity: 0,
    access: 0,
    persistence: 0,
    privacy: 0,
    continuity: 0,
  };

  if (gaps.some((gap) => gap.type === "REVERSED")) {
    zoneProbs.integrity = 0.95;
  } else if (gaps.some((gap) => gap.severity === "CRITICAL")) {
    zoneProbs.integrity = 0.8;
  } else if (gaps.length > 0) {
    zoneProbs.integrity = 0.3;
  }

  for (const threat of threats) {
    const tags = threat.risk_tags ?? [];
    if (tags.includes("PRIV_ESCALATION"))
      zoneProbs.access = Math.max(zoneProbs.access, 0.9);
    if (tags.includes("BRUTE_FORCE_TARGET"))
      zoneProbs.access = Math.max(zoneProbs.access, 0.7);
    if (tags.includes("LOG_TAMPER_ATTEMPT"))
      zoneProbs.persistence = Math.max(zoneProbs.persistence, 0.99);
    if (tags.includes("UNUSUAL_FILE_CHANGE"))
      zoneProbs.persistence = Math.max(zoneProbs.persistence, 0.75);
    if (tags.includes("SENSITIVE_FILE_ACCESS"))
      zoneProbs.privacy = Math.max(zoneProbs.privacy, 0.85);
    if (tags.includes("SERVICE_INSTABILITY"))
      zoneProbs.continuity = Math.max(zoneProbs.continuity, 0.6);
  }

  const weights = {
    integrity: 1.2,
    access: 1.2,
    persistence: 1.0,
    privacy: 0.8,
    continuity: 0.5,
  };

  let combinedSafeProb = 1;
  for (const [zone, probability] of Object.entries(zoneProbs)) {
    const adjusted = Math.min(
      probability * weights[zone as keyof typeof weights],
      0.99,
    );
    combinedSafeProb *= 1 - adjusted;
  }

  return Math.round(Math.min((1 - combinedSafeProb) * 100, 100));
}

function getSeverityTone(severity: string) {
  switch (severity) {
    case "REVERSED":
    case "CRITICAL":
      return "border-rose-500/40 bg-rose-500/10 text-rose-200";
    case "HIGH":
      return "border-amber-500/40 bg-amber-500/10 text-amber-200";
    case "MEDIUM":
      return "border-sky-500/40 bg-sky-500/10 text-sky-200";
    default:
      return "border-emerald-500/40 bg-emerald-500/10 text-emerald-200";
  }
}

function getRiskTone(score: number) {
  if (score >= 75) return "from-rose-500 to-rose-400";
  if (score >= 40) return "from-amber-500 to-orange-400";
  return "from-emerald-500 to-teal-400";
}

function Badge({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-[0.16em] uppercase ${className}`}
    >
      {children}
    </span>
  );
}

function SectionShell({
  title,
  subtitle,
  badge,
  children,
}: {
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-[28px] border border-white/10 bg-[var(--panel)] p-5 shadow-glow backdrop-blur-xl sm:p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-display text-xl font-bold text-white sm:text-2xl">
            {title}
          </h2>
          {subtitle ? (
            <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-300">
              {subtitle}
            </p>
          ) : null}
        </div>
        {badge}
      </div>
      {children}
    </section>
  );
}

function MetricCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail?: string;
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
        {label}
      </p>
      <p className="mt-2 font-display text-2xl font-bold text-white sm:text-[1.7rem]">
        {value}
      </p>
      {detail ? <p className="mt-1 text-sm text-slate-400">{detail}</p> : null}
    </div>
  );
}

function RiskMeter({ score }: { score: number }) {
  const tone = getRiskTone(score);
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/50 p-5">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-400">
            Probability of compromise
          </p>
          <div className="mt-2 flex items-end gap-3">
            <span className="font-display text-5xl font-bold text-white">
              {score}%
            </span>
            <span className="pb-1 text-sm text-slate-400">Risk score</span>
          </div>
        </div>
        <Badge className="border-white/10 bg-white/5 text-slate-200">
          Live analysis
        </Badge>
      </div>
      <div className="mt-4 h-4 overflow-hidden rounded-full bg-white/10">
        <div
          className={`h-full rounded-full bg-gradient-to-r ${tone}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}

function DetailsTable({
  headers,
  rows,
  emptyText,
}: {
  headers: string[];
  rows: ReactNode[];
  emptyText: string;
}) {
  return (
    <div className="overflow-hidden rounded-3xl border border-white/10 bg-slate-950/45">
      <div className="max-h-[32rem] overflow-auto">
        <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-950/95 text-[11px] uppercase tracking-[0.2em] text-slate-400">
            <tr>
              {headers.map((header) => (
                <th
                  key={header}
                  className="border-b border-white/10 px-4 py-3 font-semibold"
                >
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length > 0 ? (
              rows
            ) : (
              <tr>
                <td
                  className="px-4 py-8 text-center text-slate-400"
                  colSpan={headers.length}
                >
                  {emptyText}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function UploadCard({
  selectedFileName,
  currentReportName,
  threshold,
  loading,
  error,
  onFileChange,
  onThresholdChange,
  onSubmit,
}: {
  selectedFileName: string;
  currentReportName: string;
  threshold: string;
  loading: boolean;
  error: string;
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onThresholdChange: (value: string) => void;
  onSubmit: () => void;
}) {
  return (
    <div className="rounded-[30px] border border-cyan-400/20 bg-[var(--panel-strong)] p-5 shadow-glow backdrop-blur-xl sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-cyan-200/70">
            Upload section
          </p>
          <h1 className="font-display mt-2 text-3xl font-bold text-white sm:text-4xl">
            Log file analyzer
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">
            Upload a log file, tune the gap threshold, and analyze suspicious
            time gaps and threat actors in the same forensic layout used by the
            generated report.
          </p>
        </div>
        <Badge className="border-cyan-400/30 bg-cyan-400/10 text-cyan-100">
          Tailwind + React + Fetch
        </Badge>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <label className="flex cursor-pointer flex-col rounded-3xl border border-dashed border-white/15 bg-white/5 px-4 py-5 transition hover:border-cyan-400/40 hover:bg-white/7">
          <span className="text-sm font-semibold text-white">Log file</span>
          <span className="mt-1 text-sm text-slate-400">
            Choose a log file to upload for analysis.
          </span>
          <input
            type="file"
            accept=".log,.txt,.csv"
            onChange={onFileChange}
            className="mt-4 block w-full text-sm text-slate-300 file:mr-4 file:rounded-full file:border-0 file:bg-cyan-400 file:px-4 file:py-2 file:font-semibold file:text-slate-950 hover:file:bg-cyan-300"
          />
          <span className="mt-3 text-xs text-slate-500">
            Selected file: {selectedFileName || "No file selected"}
          </span>
          <span className="mt-1 text-xs text-slate-500">
            Current report: {currentReportName}
          </span>
        </label>

        <div className="rounded-3xl border border-white/10 bg-white/5 p-4">
          <label className="block text-sm font-semibold text-white">
            Threshold (seconds)
          </label>
          <input
            type="number"
            min={1}
            value={threshold}
            onChange={(event) => onThresholdChange(event.target.value)}
            className="mt-3 w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-white outline-none transition placeholder:text-slate-500 focus:border-cyan-400/60"
          />
          <p className="mt-2 text-sm text-slate-400">
            Default is 300 seconds, matching the forensic report baseline.
          </p>
          <button
            type="button"
            onClick={onSubmit}
            disabled={loading || !selectedFileName}
            className="mt-4 inline-flex w-full items-center justify-center gap-3 rounded-2xl bg-cyan-400 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400"
          >
            {loading ? (
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950" />
            ) : null}
            {loading ? "Analyzing..." : "Analyze log"}
          </button>
        </div>
      </div>

      {error ? (
        <div className="mt-4 rounded-2xl border border-rose-500/20 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      ) : null}
    </div>
  );
}

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [threshold, setThreshold] = useState("300");
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [loadedFromCache, setLoadedFromCache] = useState(false);

  useEffect(() => {
    let active = true;
    fetch(buildUrl("/api/latest-report"))
      .then(async (response) => {
        if (!response.ok) return null;
        return (await response.json()) as ForensicReport;
      })
      .then((data) => {
        if (!active || !data) return;
        setReport(data);
        setLoadedFromCache(true);
      })
      .catch(() => {
        if (!active) return;
        setLoadedFromCache(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const riskScore = calculateRisk(report ?? undefined);
  const gapCount = report?.gaps?.length ?? 0;
  const threatCount = report?.threats?.length ?? 0;
  const obfuscationCount = report?.stats?.obfuscation_count ?? 0;
  const totalLines = report?.stats?.total_lines ?? 0;
  const parsedLines = report?.stats?.parsed_lines ?? 0;
  const skippedLines = report?.stats?.skipped_lines ?? 0;
  const topThreat = [...(report?.threats ?? [])].sort(
    (left, right) => right.hits - left.hits,
  )[0];
  const topThreats = [...(report?.threats ?? [])]
    .sort((left, right) => right.hits - left.hits)
    .slice(0, 5);

  const criticalGaps = (report?.gaps ?? []).filter(
    (gap) => gap.severity === "CRITICAL",
  );
  const reversedGaps = (report?.gaps ?? []).filter(
    (gap) => gap.type === "REVERSED",
  );
  const bruteForceActors = (report?.threats ?? []).filter((threat) =>
    threat.risk_tags.includes("BRUTE_FORCE_TARGET"),
  );
  const privilegeActors = (report?.threats ?? []).filter((threat) =>
    threat.risk_tags.includes("PRIV_ESCALATION"),
  );
  const sensitiveActors = (report?.threats ?? []).filter((threat) =>
    threat.risk_tags.includes("SENSITIVE_FILE_ACCESS"),
  );
  const instabilityActors = (report?.threats ?? []).filter((threat) =>
    threat.risk_tags.includes("SERVICE_INSTABILITY"),
  );
  const obfuscatedActors = (report?.threats ?? []).filter((threat) =>
    threat.risk_tags.includes("OBFUSCATED_PAYLOAD"),
  );

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
    setError("");
  }

  async function handleAnalyze() {
    if (!selectedFile) {
      setError("Choose a log file before analyzing.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("threshold", threshold || "300");

      let response = await fetch(buildUrl("/api/analyze"), {
        method: "POST",
        body: formData,
      });

      // Retry against local Flask directly if a proxy path was unreachable.
      if (!response.ok && response.status >= 500) {
        response = await fetch("http://127.0.0.1:5000/api/analyze", {
          method: "POST",
          body: formData,
        });
      }

      const payload = (await response.json()) as ForensicReport;
      if (!response.ok) {
        throw new Error(payload.error || "Analysis failed.");
      }

      setReport(payload);
      setLoadedFromCache(false);
    } catch (analysisError) {
      if (isNetworkError(analysisError)) {
        setError(
          "NetworkError: Could not reach Flask API at http://127.0.0.1:5000. Start backend.py and retry.",
        );
      } else {
        setError(
          analysisError instanceof Error
            ? analysisError.message
            : "Unable to analyze the selected file.",
        );
      }
    } finally {
      setLoading(false);
    }
  }

  const reportFileName =
    report?.file_info?.filename ??
    report?.analysis_source?.split(/[\\/]/).pop() ??
    "sample.log";

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(120deg,rgba(56,189,248,0.06),transparent_30%),linear-gradient(250deg,rgba(15,23,42,0.15),transparent_36%)]" />
      <div className="pointer-events-none absolute left-[-10%] top-10 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[-8%] top-1/4 h-80 w-80 rounded-full bg-emerald-500/10 blur-3xl" />

      <header className="sticky top-0 z-20 border-b border-white/8 bg-slate-950/65 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
          <div>
            <p className="font-display text-lg font-bold tracking-wide text-white sm:text-xl">
              Evidence Protector Dashboard
            </p>
            <p className="text-xs uppercase tracking-[0.28em] text-slate-400">
              Suspicious gaps, threat actors, and forensic metadata
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge className="border-white/10 bg-white/5 text-slate-200">
              {loadedFromCache ? "Cached report" : "Live upload"}
            </Badge>
            <Badge className="border-cyan-400/30 bg-cyan-400/10 text-cyan-100">
              Fetch API
            </Badge>
          </div>
        </div>
      </header>

      <main className="mx-auto flex max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
          <UploadCard
            selectedFileName={selectedFile?.name ?? ""}
            currentReportName={reportFileName}
            threshold={threshold}
            loading={loading}
            error={error}
            onFileChange={handleFileChange}
            onThresholdChange={setThreshold}
            onSubmit={handleAnalyze}
          />

          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
            <RiskMeter score={riskScore} />
            <div className="rounded-3xl border border-white/10 bg-[var(--panel)] p-5 shadow-glow backdrop-blur-xl">
              <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-400">
                Evidence summary
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-2">
                <MetricCard
                  label="Timeline anomalies"
                  value={formatNumber(gapCount)}
                  detail={`${criticalGaps.length} critical gaps`}
                />
                <MetricCard
                  label="Threat actors"
                  value={formatNumber(threatCount)}
                  detail={`${bruteForceActors.length} brute-force targets`}
                />
                <MetricCard
                  label="Parsed lines"
                  value={formatNumber(parsedLines)}
                  detail={`of ${formatNumber(totalLines)} total lines`}
                />
                <MetricCard
                  label="Obfuscation"
                  value={formatNumber(obfuscationCount)}
                  detail={`${skippedLines} noisy lines skipped`}
                />
              </div>
            </div>
          </div>
        </section>

        {report ? (
          <>
            <SectionShell
              title="System context"
              subtitle="The generated dashboard preserves the system, performance, and file metadata already present in the forensic report."
              badge={
                <Badge className="border-white/10 bg-white/5 text-slate-200">
                  {report.stats.log_type}
                </Badge>
              }
            >
              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                  label="Host"
                  value={report.system_info.host}
                  detail={report.system_info.os}
                />
                <MetricCard
                  label="Processor"
                  value={report.system_info.cpu || "Unknown"}
                  detail={`${report.system_info.arch} architecture`}
                />
                <MetricCard
                  label="Processing time"
                  value={`${report.performance.time}s`}
                  detail={`${report.performance.lps.toLocaleString()} lines/sec`}
                />
                <MetricCard
                  label="Log span"
                  value={formatDuration(report.stats.log_span_sec)}
                  detail={`Scanned at ${formatDate(report.system_info.ts)}`}
                />
              </div>

              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div className="rounded-3xl border border-white/10 bg-slate-950/45 p-4">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
                    File metadata
                  </p>
                  <div className="mt-3 space-y-2 text-sm text-slate-300">
                    <div className="flex items-center justify-between gap-3">
                      <span>File</span>
                      <span className="text-white">
                        {report.file_info?.filename ?? reportFileName}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Path</span>
                      <span className="max-w-[60%] truncate text-slate-200">
                        {report.file_info?.path ??
                          report.analysis_source ??
                          "—"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Size</span>
                      <span className="text-white">
                        {formatBytes(report.file_info?.size_bytes)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Modified</span>
                      <span className="text-white">
                        {formatDate(report.file_info?.modified_at)}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="rounded-3xl border border-white/10 bg-slate-950/45 p-4">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
                    Processing intelligence
                  </p>
                  <div className="mt-3 space-y-2 text-sm text-slate-300">
                    <div className="flex items-center justify-between gap-3">
                      <span>Total lines</span>
                      <span className="text-white">
                        {formatNumber(report.stats.total_lines)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Parsed lines</span>
                      <span className="text-white">
                        {formatNumber(report.stats.parsed_lines)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Skipped lines</span>
                      <span className="text-white">
                        {formatNumber(report.stats.skipped_lines)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <span>Threshold</span>
                      <span className="text-white">
                        {report.threshold_seconds ?? threshold} sec
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </SectionShell>

            <SectionShell
              title="Forensic reconstruction"
              subtitle="This narrative mirrors the report snapshot: anomaly count, actor count, and the most active source are surfaced up front."
              badge={
                <Badge className="border-slate-500/30 bg-white/5 text-slate-200">
                  Generated{" "}
                  {formatDate(
                    report.analysis_generated_at ?? report.server_timestamp,
                  )}
                </Badge>
              }
            >
              <div className="rounded-[28px] border-l-4 border-cyan-400 bg-slate-950/70 p-5 text-slate-200 shadow-inner shadow-cyan-950/20">
                <p className="text-sm leading-7 text-slate-300">
                  Analysis of{" "}
                  <span className="font-semibold text-white">
                    {formatNumber(report.stats.total_lines)}
                  </span>{" "}
                  lines revealed{" "}
                  <span className="font-semibold text-white">
                    {formatNumber(threatCount)}
                  </span>{" "}
                  actors. Integrity confidence is{" "}
                  <span className="font-semibold text-white">
                    {report.gaps.length > 0 ? "LOW" : "HIGH"}
                  </span>
                  . The most significant finding is{" "}
                  <span className="font-semibold text-white">
                    {topThreat ? formatNumber(topThreat.hits) : 0}
                  </span>{" "}
                  logged events from a single source IP.
                </p>

                <div className="mt-4 grid gap-3 sm:grid-cols-3">
                  <MetricCard
                    label="Top actor"
                    value={topThreat?.ip ?? "None"}
                    detail={`${topThreat ? formatNumber(topThreat.hits) : 0} hits`}
                  />
                  <MetricCard
                    label="Threat tags"
                    value={topThreat?.risk_tags?.length?.toString() ?? "0"}
                    detail={
                      topThreat?.risk_tags?.slice(0, 3).join(", ") || "No tags"
                    }
                  />
                  <MetricCard
                    label="Risk score"
                    value={`${riskScore}%`}
                    detail="Computed from timeline and behavior"
                  />
                </div>
              </div>
            </SectionShell>

            <SectionShell
              title="Categorized forensic evidence"
              subtitle="The dashboard preserves the report's zoning structure while keeping the upload workflow on the same page."
              badge={
                <Badge className="border-white/10 bg-white/5 text-slate-200">
                  {reversedGaps.length + criticalGaps.length} integrity events
                </Badge>
              }
            >
              <div className="space-y-4">
                <details
                  open
                  className="group rounded-3xl border border-white/10 bg-slate-950/40 overflow-hidden"
                >
                  <summary className="flex cursor-pointer list-none items-center gap-3 border-l-4 border-slate-500 px-4 py-4 text-base font-semibold text-white [&::-webkit-details-marker]:hidden">
                    Zone 1: Timeline & Integrity
                    <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-200">
                      {formatNumber(gapCount)}
                    </span>
                  </summary>
                  <div className="border-t border-white/10 p-4">
                    <div className="space-y-4">
                      <details
                        open
                        className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                      >
                        <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                          Timeline gaps
                          <span className="ml-auto rounded-full border border-rose-400/30 bg-rose-500/10 px-2.5 py-1 text-xs text-rose-200">
                            {formatNumber(report.gaps.length)}
                          </span>
                        </summary>
                        <div className="border-t border-white/10 p-3">
                          <DetailsTable
                            headers={["Type", "Duration", "Window", "Lines"]}
                            rows={report.gaps.map((gap: GapEntry) => (
                              <tr
                                key={`${gap.start_line}-${gap.end_line}-${gap.gap_start}`}
                                className="border-t border-white/5 hover:bg-white/[0.02]"
                              >
                                <td className="px-4 py-3 align-top">
                                  <span
                                    className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] ${getSeverityTone(gap.severity)}`}
                                  >
                                    {gap.severity}
                                  </span>
                                </td>
                                <td className="px-4 py-3 align-top text-slate-200">
                                  {gap.duration_human}
                                </td>
                                <td className="px-4 py-3 align-top text-slate-300">
                                  {formatDate(gap.gap_start)} →{" "}
                                  {formatDate(gap.gap_end)}
                                </td>
                                <td className="px-4 py-3 align-top text-slate-200">
                                  {gap.start_line}-{gap.end_line}
                                </td>
                              </tr>
                            ))}
                            emptyText="No timeline gaps were detected."
                          />
                        </div>
                      </details>

                      <details
                        open
                        className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                      >
                        <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                          Time reversals
                          <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-200">
                            {formatNumber(reversedGaps.length)}
                          </span>
                        </summary>
                        <div className="border-t border-white/10 p-3">
                          <DetailsTable
                            headers={["Window", "Lines", "Severity"]}
                            rows={reversedGaps.map((gap) => (
                              <tr
                                key={`${gap.start_line}-${gap.end_line}-${gap.gap_start}`}
                                className="border-t border-white/5 hover:bg-white/[0.02]"
                              >
                                <td className="px-4 py-3 align-top text-slate-300">
                                  {formatDate(gap.gap_start)} →{" "}
                                  {formatDate(gap.gap_end)}
                                </td>
                                <td className="px-4 py-3 align-top text-slate-200">
                                  {gap.start_line}-{gap.end_line}
                                </td>
                                <td className="px-4 py-3 align-top text-slate-200">
                                  {gap.severity}
                                </td>
                              </tr>
                            ))}
                            emptyText="No reversals detected."
                          />
                        </div>
                      </details>
                    </div>
                  </div>
                </details>

                <details
                  open
                  className="group rounded-3xl border border-white/10 bg-slate-950/40 overflow-hidden"
                >
                  <summary className="flex cursor-pointer list-none items-center gap-3 border-l-4 border-cyan-500 px-4 py-4 text-base font-semibold text-white [&::-webkit-details-marker]:hidden">
                    Zone 2: Access & Control
                    <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-200">
                      {formatNumber(
                        bruteForceActors.length + privilegeActors.length,
                      )}
                    </span>
                  </summary>
                  <div className="border-t border-white/10 p-4 space-y-4">
                    <details
                      open
                      className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                    >
                      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                        Brute force activity
                        <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-200">
                          {formatNumber(bruteForceActors.length)}
                        </span>
                      </summary>
                      <div className="border-t border-white/10 p-3">
                        <DetailsTable
                          headers={["IP", "Hits", "Failures", "Span", "Tags"]}
                          rows={bruteForceActors.map((threat: ThreatActor) => (
                            <tr
                              key={`bf-${threat.ip}`}
                              className="border-t border-white/5 hover:bg-white/[0.02]"
                            >
                              <td className="px-4 py-3 align-top font-semibold text-white">
                                {threat.ip}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.hits)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.failed_attempts ?? 0)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-300">
                                {threat.span_human}
                              </td>
                              <td className="px-4 py-3 align-top">
                                <div className="flex flex-wrap gap-2">
                                  {threat.risk_tags.slice(0, 5).map((tag) => (
                                    <span
                                      key={`${threat.ip}-${tag}`}
                                      className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-cyan-100"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              </td>
                            </tr>
                          ))}
                          emptyText="No brute force activity detected."
                        />
                      </div>
                    </details>

                    <details
                      open
                      className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                    >
                      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                        Privilege escalation attempts
                        <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-200">
                          {formatNumber(privilegeActors.length)}
                        </span>
                      </summary>
                      <div className="border-t border-white/10 p-3">
                        <DetailsTable
                          headers={["IP", "Hits", "Failures", "Span", "Tags"]}
                          rows={privilegeActors.map((threat: ThreatActor) => (
                            <tr
                              key={`pe-${threat.ip}`}
                              className="border-t border-white/5 hover:bg-white/[0.02]"
                            >
                              <td className="px-4 py-3 align-top font-semibold text-white">
                                {threat.ip}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.hits)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.failed_attempts ?? 0)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-300">
                                {threat.span_human}
                              </td>
                              <td className="px-4 py-3 align-top">
                                <div className="flex flex-wrap gap-2">
                                  {threat.risk_tags.slice(0, 5).map((tag) => (
                                    <span
                                      key={`${threat.ip}-${tag}`}
                                      className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-cyan-100"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              </td>
                            </tr>
                          ))}
                          emptyText="No privilege escalation attempts detected."
                        />
                      </div>
                    </details>
                  </div>
                </details>

                <details
                  open
                  className="group rounded-3xl border border-white/10 bg-slate-950/40 overflow-hidden"
                >
                  <summary className="flex cursor-pointer list-none items-center gap-3 border-l-4 border-emerald-500 px-4 py-4 text-base font-semibold text-white [&::-webkit-details-marker]:hidden">
                    Zone 3: Obfuscation & Data
                    <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs font-semibold text-slate-200">
                      {formatNumber(obfuscationCount)}
                    </span>
                  </summary>
                  <div className="border-t border-white/10 p-4 space-y-4">
                    <div className="rounded-3xl border border-white/10 bg-white/5 p-4 text-sm text-slate-300">
                      Lines with high Shannon entropy (&gt;5.0) indicate packed
                      or encrypted payloads.
                    </div>

                    <details
                      open
                      className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                    >
                      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                        Obfuscated payloads
                        <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-200">
                          {formatNumber(obfuscatedActors.length)}
                        </span>
                      </summary>
                      <div className="border-t border-white/10 p-3">
                        <DetailsTable
                          headers={["IP", "Hits", "Markers"]}
                          rows={obfuscatedActors.map((threat) => (
                            <tr
                              key={`ob-${threat.ip}`}
                              className="border-t border-white/5 hover:bg-white/[0.02]"
                            >
                              <td className="px-4 py-3 align-top font-semibold text-white">
                                {threat.ip}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.hits)}
                              </td>
                              <td className="px-4 py-3 align-top">
                                <Badge className="border-rose-400/30 bg-rose-500/10 text-rose-100">
                                  ENTROPY_ALERT
                                </Badge>
                              </td>
                            </tr>
                          ))}
                          emptyText="No obfuscated payloads detected."
                        />
                      </div>
                    </details>

                    <details
                      open
                      className="group rounded-3xl border border-white/10 bg-white/5 overflow-hidden"
                    >
                      <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-4 text-sm font-semibold text-white [&::-webkit-details-marker]:hidden">
                        Sensitive access & service instability
                        <span className="ml-auto rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-200">
                          {formatNumber(
                            sensitiveActors.length + instabilityActors.length,
                          )}
                        </span>
                      </summary>
                      <div className="border-t border-white/10 p-3 grid gap-4 lg:grid-cols-2">
                        <DetailsTable
                          headers={["Sensitive access IP", "Hits", "Tags"]}
                          rows={sensitiveActors.map((threat) => (
                            <tr
                              key={`sa-${threat.ip}`}
                              className="border-t border-white/5 hover:bg-white/[0.02]"
                            >
                              <td className="px-4 py-3 align-top font-semibold text-white">
                                {threat.ip}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.hits)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-300">
                                {threat.risk_tags.slice(0, 4).join(", ")}
                              </td>
                            </tr>
                          ))}
                          emptyText="No sensitive file access detected."
                        />
                        <DetailsTable
                          headers={["Instability IP", "Hits", "Tags"]}
                          rows={instabilityActors.map((threat) => (
                            <tr
                              key={`si-${threat.ip}`}
                              className="border-t border-white/5 hover:bg-white/[0.02]"
                            >
                              <td className="px-4 py-3 align-top font-semibold text-white">
                                {threat.ip}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-200">
                                {formatNumber(threat.hits)}
                              </td>
                              <td className="px-4 py-3 align-top text-slate-300">
                                {threat.risk_tags.slice(0, 4).join(", ")}
                              </td>
                            </tr>
                          ))}
                          emptyText="No service instability detected."
                        />
                      </div>
                    </details>
                  </div>
                </details>
              </div>
            </SectionShell>

            <SectionShell
              title="Top threat actors"
              subtitle="The most active IPs are surfaced here, matching the structure of the generated HTML report while keeping the dashboard compact."
              badge={
                <Badge className="border-white/10 bg-white/5 text-slate-200">
                  Top {topThreats.length}
                </Badge>
              }
            >
              <DetailsTable
                headers={[
                  "Entity (IP)",
                  "Hits",
                  "Failures",
                  "Span",
                  "Risk indicators",
                ]}
                rows={topThreats.map((threat) => (
                  <tr
                    key={threat.ip}
                    className="border-t border-white/5 hover:bg-white/[0.02]"
                  >
                    <td className="px-4 py-3 align-top font-semibold text-white">
                      {threat.ip}
                    </td>
                    <td className="px-4 py-3 align-top text-slate-200">
                      {formatNumber(threat.hits)}
                    </td>
                    <td className="px-4 py-3 align-top text-slate-200">
                      {formatNumber(threat.failed_attempts ?? 0)}
                    </td>
                    <td className="px-4 py-3 align-top text-slate-300">
                      {threat.span_human}
                    </td>
                    <td className="px-4 py-3 align-top">
                      <div className="flex flex-wrap gap-2">
                        {threat.risk_tags.slice(0, 4).map((tag) => (
                          <span
                            key={`${threat.ip}-${tag}`}
                            className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-200"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
                emptyText="No threats detected in this scan."
              />
            </SectionShell>

            <footer className="pb-6 text-center text-xs uppercase tracking-[0.26em] text-slate-500">
              Evidence Protector Engine | {formatNumber(parsedLines)} parse
              success | {formatNumber(skippedLines)} noisy lines
            </footer>
          </>
        ) : (
          <section className="rounded-[30px] border border-white/10 bg-[var(--panel)] p-8 text-center shadow-glow backdrop-blur-xl">
            <p className="font-display text-2xl font-bold text-white">
              No report loaded yet
            </p>
            <p className="mx-auto mt-3 max-w-2xl text-sm leading-6 text-slate-300">
              The dashboard will hydrate automatically from the latest cached
              analysis, or you can upload a new log file to generate a fresh
              forensic report.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;

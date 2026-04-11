import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { io } from "socket.io-client";
import type { ForensicReport, GapEntry, ThreatActor } from "./types";
import CountUp from "./components/CountUp";
import Badge from "./components/ui/Badge";
import SectionShell from "./components/ui/SectionShell";
import MetricCard from "./components/ui/MetricCard";
import RiskMeter from "./components/ui/RiskMeter";
import DetailsTable from "./components/ui/DetailsTable";
import UploadCard from "./components/ui/UploadCard";
import ScrollReveal from "./components/ui/ScrollReveal";
import ActivityTimelineChart from "./components/charts/ActivityTimelineChart";
import BubblePlot from "./components/charts/BubblePlot";
import type {
  ActivityBucket,
  BubbleGroup,
  BubblePoint,
} from "./components/charts/types";
import AppHeader from "./components/layout/AppHeader";
import HomeHeroSection from "./components/home/HomeHeroSection";
import type { LocalCalendarDate } from "./components/home/types";

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://127.0.0.1:5000";

function buildUrl(path: string) {
  return `${API_BASE}${path}`;
}

function normalizeReport(payload: ForensicReport): ForensicReport {
  return {
    ...payload,
    gaps: Array.isArray(payload.gaps) ? payload.gaps : [],
    threats: Array.isArray(payload.threats) ? payload.threats : [],
    system_info: payload.system_info ?? {
      os: "Unknown OS",
      ver: "Unknown",
      arch: "Unknown",
      host: "Unknown host",
      cpu: "Unknown CPU",
      ts: new Date().toISOString(),
    },
    performance: payload.performance ?? {
      time: 0,
      lps: 0,
    },
    stats: payload.stats ?? {
      log_type: "unknown",
      total_lines: 0,
      parsed_lines: 0,
      skipped_lines: 0,
      log_span_sec: 0,
      obfuscation_count: 0,
    },
  };
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

type ViewMode = "home" | "dashboard";

function formatTimeLabel(value: Date, includeDate: boolean) {
  return includeDate
    ? value.toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : value.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function buildActivityTimeline(report?: ForensicReport): ActivityBucket[] {
  if (!report) return [];

  const timestamps: Date[] = [];
  for (const gap of report.gaps ?? []) {
    const start = new Date(gap.gap_start);
    const end = new Date(gap.gap_end);
    if (!Number.isNaN(start.getTime())) timestamps.push(start);
    if (!Number.isNaN(end.getTime())) timestamps.push(end);
  }

  for (const threat of report.threats ?? []) {
    const active = new Date(threat.last_active);
    if (!Number.isNaN(active.getTime())) timestamps.push(active);
  }

  if (timestamps.length === 0) return [];

  timestamps.sort((left, right) => left.getTime() - right.getTime());
  const minTime = timestamps[0].getTime();
  const maxTime = timestamps[timestamps.length - 1].getTime();
  const bucketCount = 8;
  const spanMs = Math.max(maxTime - minTime, 1);
  const bucketSize = spanMs / bucketCount;
  const includeDate = spanMs >= 24 * 60 * 60 * 1000;

  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const bucketStart = new Date(minTime + bucketSize * index);
    return {
      timeLabel: formatTimeLabel(bucketStart, includeDate),
      count: 0,
    };
  });

  for (const timestamp of timestamps) {
    const index = Math.min(
      bucketCount - 1,
      Math.floor((timestamp.getTime() - minTime) / bucketSize),
    );
    buckets[index].count += 1;
  }

  return buckets;
}

function isUploadedCache(report?: ForensicReport | null) {
  if (!report) return false;
  const source = report.analysis_source ?? report.file_info?.path ?? "";
  const fileName = report.file_info?.filename ?? "";
  return (
    source.includes("forensic_upload_") ||
    fileName.startsWith("forensic_upload_")
  );
}

function resolveBubbleGroup(tags: string[]): BubbleGroup {
  if (
    tags.includes("PRIV_ESCALATION") ||
    tags.includes("BRUTE_FORCE_TARGET") ||
    tags.includes("FAILED_LOGIN")
  ) {
    return "Access";
  }
  if (
    tags.includes("LOG_TAMPER_ATTEMPT") ||
    tags.includes("UNUSUAL_FILE_CHANGE")
  ) {
    return "Integrity";
  }
  if (
    tags.includes("SENSITIVE_FILE_ACCESS") ||
    tags.includes("OBFUSCATED_PAYLOAD")
  ) {
    return "Data";
  }
  if (tags.includes("SERVICE_INSTABILITY")) {
    return "Availability";
  }
  return "Recon";
}

function buildBubblePoints(report?: ForensicReport): BubblePoint[] {
  if (!report) return [];
  return (report.threats ?? []).map((threat) => {
    const failures = threat.failed_attempts ?? 0;
    const tags = threat.risk_tags ?? [];
    return {
      id: threat.ip,
      label: threat.ip,
      group: resolveBubbleGroup(tags),
      xValue: threat.hits + failures * 2,
      yValue: tags.length * 12 + (failures > 0 ? Math.min(failures, 30) : 0),
      sizeValue: Math.max(6, Math.sqrt(Math.max(threat.hits, 1)) * 2.4),
      hits: threat.hits,
      failures,
      tags,
    };
  });
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

function App() {
  const [viewMode, setViewMode] = useState<ViewMode>("home");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [threshold, setThreshold] = useState("300");
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [loadedFromCache, setLoadedFromCache] = useState(false);
  const [calendarRows, setCalendarRows] = useState<LocalCalendarDate[]>([]);
  const [calendarLoading, setCalendarLoading] = useState(false);
  const [calendarDate, setCalendarDate] = useState("");
  const [calendarFile, setCalendarFile] = useState("");
  const reportRef = useRef<ForensicReport | null>(null);

  const selectedCalendarEntry = calendarRows.find(
    (row) => row.date === calendarDate,
  );
  const availableCalendarFiles = selectedCalendarEntry?.files ?? [];
  const selectedCalendarIndex = availableCalendarFiles.findIndex(
    (item) => item.filename === calendarFile,
  );

  async function fetchPeriodicReports() {
    const response = await fetch(buildUrl("/api/reports"));
    if (!response.ok) {
      throw new Error("Periodic report index is unavailable.");
    }
    return (await response.json()) as LocalCalendarDate[];
  }

  function applyBackendReport(nextReport: ForensicReport) {
    const normalized = normalizeReport(nextReport);
    setReport((currentReport) => {
      if (currentReport && isUploadedCache(currentReport)) {
        return currentReport;
      }
      return normalized;
    });
    setLoadedFromCache(true);
    setError("");
  }

  useEffect(() => {
    reportRef.current = report;
  }, [report]);

  useEffect(() => {
    try {
      const savedTheme = localStorage.getItem("ldfta-theme");
      if (savedTheme === "light" || savedTheme === "dark") {
        setTheme(savedTheme);
        return;
      }
      if (window.matchMedia("(prefers-color-scheme: light)").matches) {
        setTheme("light");
      }
    } catch {
      // Ignore storage access errors and keep default theme.
    }
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("ldfta-theme", theme);
    } catch {
      // Ignore storage access errors.
    }
  }, [theme]);

  async function loadCalendar() {
    setCalendarLoading(true);
    setError("");
    try {
      const rows = await fetchPeriodicReports();
      setCalendarRows(rows);
      if (rows.length > 0 && !calendarDate) {
        setCalendarDate(rows[0].date);
        setCalendarFile(rows[0].files[0]?.filename ?? "");
      }
      if (rows.length === 0) {
        setCalendarDate("");
        setCalendarFile("");
      }
    } catch (calendarError) {
      setCalendarRows([]);
      setCalendarDate("");
      setCalendarFile("");
      setError(
        calendarError instanceof Error
          ? calendarError.message
          : "Periodic reports could not be loaded.",
      );
    } finally {
      setCalendarLoading(false);
    }
  }

  useEffect(() => {
    loadCalendar();
  }, []);

  useEffect(() => {
    const socket = io(API_BASE, {
      autoConnect: true,
    });

    socket.on("new_forensic_data", (payload: ForensicReport) => {
      applyBackendReport(normalizeReport(payload));
      void loadCalendar();
    });

    socket.on("scan_error", (payload: { error?: string }) => {
      const currentReport = reportRef.current;
      if (!currentReport || !isUploadedCache(currentReport)) {
        setError(payload.error || "Backend scan failed.");
      }
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(() => {
    if (!calendarDate || availableCalendarFiles.length === 0) {
      setCalendarFile("");
      return;
    }

    const exists = availableCalendarFiles.some(
      (item) => item.filename === calendarFile,
    );
    if (!exists) {
      setCalendarFile(availableCalendarFiles[0].filename);
    }
  }, [calendarDate, availableCalendarFiles, calendarFile]);

  const activityTimeline = buildActivityTimeline(report ?? undefined);
  const bubblePoints = useMemo(
    () => buildBubblePoints(report ?? undefined),
    [report],
  );

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

  async function handleAnalyzeLocalFile() {
    if (!calendarFile) {
      setError("Choose a periodic report from the selected date first.");
      return;
    }

    const selectedReport = availableCalendarFiles.find(
      (item) => item.filename === calendarFile,
    );
    if (!selectedReport?.url) {
      setError("Selected report is missing a load URL.");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const response = await fetch(buildUrl(selectedReport.url));
      const payload = (await response.json()) as ForensicReport;
      if (!response.ok) {
        throw new Error(payload.error || "Report load failed.");
      }
      setReport(normalizeReport(payload));
      setLoadedFromCache(true);
      setViewMode("dashboard");
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : "Unable to load the selected periodic report.",
      );
    } finally {
      setLoading(false);
    }
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

      const response = await fetch(buildUrl("/api/analyze/manual"), {
        method: "POST",
        body: formData,
      });

      const payload = (await response.json()) as ForensicReport;
      if (!response.ok) {
        throw new Error(payload.error || "Analysis failed.");
      }

      setReport(normalizeReport(payload));
      setLoadedFromCache(false);
      setViewMode("dashboard");
      void loadCalendar();
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
    <div className="app-shell relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(120deg,rgba(56,189,248,0.06),transparent_30%),linear-gradient(250deg,rgba(15,23,42,0.15),transparent_36%)]" />
      <div className="pointer-events-none absolute left-[-10%] top-10 h-72 w-72 rounded-full bg-cyan-500/10 blur-3xl" />
      <div className="pointer-events-none absolute right-[-8%] top-1/4 h-80 w-80 rounded-full bg-emerald-500/10 blur-3xl" />

      <AppHeader
        theme={theme}
        onAnalyzeUpload={handleAnalyze}
        analyzeDisabled={loading || !selectedFile}
        analyzeLabel={loading ? "Analyzing..." : "Analyze upload"}
        onToggleTheme={() =>
          setTheme((current) => (current === "dark" ? "light" : "dark"))
        }
      />

      <main className="mx-auto flex max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        {viewMode === "home" ? (
          <ScrollReveal threshold={0.1} delayMs={40}>
            <HomeHeroSection
              theme={theme}
              selectedFileName={selectedFile?.name ?? ""}
              threshold={threshold}
              loading={loading}
              onFileChange={handleFileChange}
              onThresholdChange={setThreshold}
              onAnalyzeUpload={handleAnalyze}
              calendarRows={calendarRows}
              calendarLoading={calendarLoading}
              calendarDate={calendarDate}
              calendarFile={calendarFile}
              availableCalendarFiles={availableCalendarFiles}
              selectedCalendarIndex={selectedCalendarIndex}
              onRefreshCalendar={loadCalendar}
              onCalendarDateChange={(nextDate) => {
                setCalendarDate(nextDate);
                const nextRow = calendarRows.find(
                  (row) => row.date === nextDate,
                );
                setCalendarFile(nextRow?.files[0]?.filename ?? "");
              }}
              onCalendarFileChange={setCalendarFile}
              onAnalyzeLocal={handleAnalyzeLocalFile}
            />
          </ScrollReveal>
        ) : null}

        {viewMode === "dashboard" ? (
          <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
            <ScrollReveal threshold={0.08} delayMs={20}>
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
            </ScrollReveal>

            <ScrollReveal threshold={0.08} delayMs={120}>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
                <RiskMeter score={riskScore} />
                <div className="rounded-3xl border border-white/10 bg-[var(--panel)] p-5 shadow-glow backdrop-blur-xl">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.28em] text-slate-400">
                    Evidence summary
                  </p>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-2">
                    <MetricCard
                      label="Timeline anomalies"
                      value={
                        <CountUp
                          to={gapCount}
                          duration={1.2}
                          separator=","
                          startWhen
                        />
                      }
                      detail={`${criticalGaps.length} critical gaps`}
                    />
                    <MetricCard
                      label="Threat actors"
                      value={
                        <CountUp
                          to={threatCount}
                          duration={1.2}
                          separator=","
                          startWhen
                        />
                      }
                      detail={`${bruteForceActors.length} brute-force targets`}
                    />
                    <MetricCard
                      label="Parsed lines"
                      value={
                        <CountUp
                          to={parsedLines}
                          duration={1.4}
                          separator=","
                          startWhen
                        />
                      }
                      detail={`of ${formatNumber(totalLines)} total lines`}
                    />
                    <MetricCard
                      label="Obfuscation"
                      value={
                        <CountUp
                          to={obfuscationCount}
                          duration={1.2}
                          separator=","
                          startWhen
                        />
                      }
                      detail={`${skippedLines} noisy lines skipped`}
                    />
                  </div>
                </div>
              </div>
            </ScrollReveal>
          </section>
        ) : null}

        {viewMode === "dashboard" ? (
          report ? (
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
                  <div className="rounded-3xl border border-cyan-400/20 bg-cyan-500/10 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-100/80">
                      Host
                    </p>
                    <p className="mt-2 font-display text-2xl font-bold text-white">
                      {report.system_info.host}
                    </p>
                    <p className="mt-1 text-sm text-cyan-50/80">
                      {report.system_info.os}
                    </p>
                  </div>
                  <div className="rounded-3xl border border-fuchsia-400/20 bg-fuchsia-500/10 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-fuchsia-100/80">
                      Processor
                    </p>
                    <p className="mt-2 text-sm font-semibold leading-6 text-white">
                      {report.system_info.cpu || "Unknown"}
                    </p>
                    <p className="mt-1 text-sm text-fuchsia-50/80">
                      {report.system_info.arch} architecture
                    </p>
                  </div>
                  <div className="rounded-3xl border border-emerald-400/20 bg-emerald-500/10 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-emerald-100/80">
                      Processing time
                    </p>
                    <p className="mt-2 font-display text-2xl font-bold text-white">
                      {report.performance.time}s
                    </p>
                    <p className="mt-1 text-sm text-emerald-50/80">
                      {report.performance.lps.toLocaleString()} lines/sec
                    </p>
                  </div>
                  <div className="rounded-3xl border border-amber-400/20 bg-amber-500/10 p-4">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-amber-100/80">
                      Log span
                    </p>
                    <p className="mt-2 font-display text-2xl font-bold text-white">
                      {formatDuration(report.stats.log_span_sec)}
                    </p>
                    <p className="mt-1 text-sm text-amber-50/80">
                      Scanned at {formatDate(report.system_info.ts)}
                    </p>
                  </div>
                </div>

                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <div className="rounded-3xl border border-white/10 bg-slate-950/50 p-5">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">
                        File metadata
                      </p>
                      <Badge className="border-white/10 bg-white/5 text-slate-200">
                        {report.file_info?.extension || "LOG"}
                      </Badge>
                    </div>
                    <div className="space-y-3 text-sm text-slate-300">
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">File</span>
                        <span className="font-semibold text-white break-all">
                          {report.file_info?.filename ?? reportFileName}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Path</span>
                        <span className="font-mono text-[12px] leading-6 text-slate-200 break-all">
                          {report.file_info?.path ??
                            report.analysis_source ??
                            "—"}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Size</span>
                        <span className="font-semibold text-white">
                          {formatBytes(report.file_info?.size_bytes)}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Modified</span>
                        <span className="font-semibold text-white">
                          {formatDate(report.file_info?.modified_at)}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-3xl border border-white/10 bg-slate-950/50 p-5">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">
                        Processing intelligence
                      </p>
                      <Badge className="border-cyan-400/30 bg-cyan-400/10 text-cyan-100">
                        {report.stats.log_type}
                      </Badge>
                    </div>
                    <div className="space-y-3 text-sm text-slate-300">
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Total lines</span>
                        <span className="font-semibold text-white">
                          {formatNumber(report.stats.total_lines)}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Parsed lines</span>
                        <span className="font-semibold text-white">
                          {formatNumber(report.stats.parsed_lines)}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 border-b border-white/10 pb-2 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Skipped lines</span>
                        <span className="font-semibold text-white">
                          {formatNumber(report.stats.skipped_lines)}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 gap-1 sm:grid-cols-[140px_1fr] sm:gap-2">
                        <span className="text-slate-400">Threshold</span>
                        <span className="font-semibold text-white">
                          {report.threshold_seconds ?? threshold} sec
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </SectionShell>

              <SectionShell
                title="Activity timeline"
                subtitle="Time is plotted on the X axis and the number of suspicious activities is plotted on the Y axis."
                badge={
                  <Badge className="border-white/10 bg-white/5 text-slate-200">
                    {activityTimeline.length} time buckets
                  </Badge>
                }
              >
                <ActivityTimelineChart
                  buckets={activityTimeline}
                  theme={theme}
                />
              </SectionShell>

              <SectionShell
                title="Threat bubble map"
                subtitle="A creative bubble plot where each threat actor is placed by behavior intensity and complexity, with bubble size indicating actor volume."
                badge={
                  <Badge className="border-white/10 bg-white/5 text-slate-200">
                    {bubblePoints.length} actors plotted
                  </Badge>
                }
              >
                <BubblePlot points={bubblePoints} theme={theme} />
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
                      value={
                        <CountUp
                          to={topThreat?.risk_tags?.length ?? 0}
                          duration={1}
                          separator=","
                          startWhen
                        />
                      }
                      detail={
                        topThreat?.risk_tags?.slice(0, 3).join(", ") ||
                        "No tags"
                      }
                    />
                    <MetricCard
                      label="Risk score"
                      value={
                        <>
                          <CountUp
                            to={riskScore}
                            duration={1.1}
                            separator=","
                            startWhen
                          />
                          %
                        </>
                      }
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
                            rows={bruteForceActors.map(
                              (threat: ThreatActor) => (
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
                                      {threat.risk_tags
                                        .slice(0, 5)
                                        .map((tag) => (
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
                              ),
                            )}
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
                        Lines with high Shannon entropy (&gt;5.0) indicate
                        packed or encrypted payloads.
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
          )
        ) : null}

        <footer className="pt-2 pb-6 text-center text-[11px] text-slate-400">
          Log Detector and Foreign Threat Analysis
        </footer>
      </main>
    </div>
  );
}

export default App;

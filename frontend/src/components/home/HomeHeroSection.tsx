import type { ChangeEvent } from "react";
import dayjs, { type Dayjs } from "dayjs";
import { DateCalendar, LocalizationProvider } from "@mui/x-date-pickers";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import AnimatedList from "../AnimatedList";
import type { LocalCalendarDate } from "./types";

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

export default function HomeHeroSection({
  theme,
  selectedFileName,
  threshold,
  loading,
  onFileChange,
  onThresholdChange,
  onAnalyzeUpload,
  calendarRows,
  calendarLoading,
  calendarDate,
  calendarFile,
  availableCalendarFiles,
  selectedCalendarIndex,
  onRefreshCalendar,
  onCalendarDateChange,
  onCalendarFileChange,
  onAnalyzeLocal,
}: {
  theme: "dark" | "light";
  selectedFileName: string;
  threshold: string;
  loading: boolean;
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onThresholdChange: (value: string) => void;
  onAnalyzeUpload: () => void;
  calendarRows: LocalCalendarDate[];
  calendarLoading: boolean;
  calendarDate: string;
  calendarFile: string;
  availableCalendarFiles: LocalCalendarDate["files"];
  selectedCalendarIndex: number;
  onRefreshCalendar: () => void;
  onCalendarDateChange: (nextDate: string) => void;
  onCalendarFileChange: (filename: string) => void;
  onAnalyzeLocal: () => void;
}) {
  const isLight = theme === "light";
  const calendarValue = calendarDate ? dayjs(calendarDate) : null;

  return (
    <section className="home-hero-gloss rounded-[30px] border border-white/10 bg-[var(--panel-strong)] p-6 shadow-glow backdrop-blur-xl">
      <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-cyan-200/70">
        Home
      </p>
      <h1 className="font-display mt-2 text-3xl font-bold text-white sm:text-5xl">
        Detect log anomalies and foreign threat behavior in one control plane
      </h1>
      <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300 sm:text-base">
        Run manual forensic scans from uploads, jump into historical logs using
        date-driven local file replay, and inspect timeline + threat
        intelligence with visual analytics.
      </p>
      <div className="mt-5 grid gap-4 lg:grid-cols-2">
        <div className="home-option-card rounded-3xl border border-cyan-400/25 bg-cyan-500/10 p-5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-100/80">
            Option 1: Manual Scan
          </p>
          <p className="mt-2 text-sm text-cyan-50/80">
            Upload a log file directly from your system and run on-demand
            analysis with your threshold configuration.
          </p>
          <label className="mt-4 block text-xs uppercase tracking-[0.18em] text-cyan-100/70">
            Upload log file
          </label>
          <input
            type="file"
            accept=".log,.txt,.csv"
            onChange={onFileChange}
            className="mt-2 block w-full text-sm text-cyan-100 file:mr-4 file:rounded-full file:border-0 file:bg-cyan-300 file:px-4 file:py-2 file:font-semibold file:text-slate-950 hover:file:bg-cyan-200"
          />
          <label className="mt-4 block text-xs uppercase tracking-[0.18em] text-cyan-100/70">
            Threshold (seconds)
          </label>
          <input
            type="number"
            min={1}
            value={threshold}
            onChange={(event) => onThresholdChange(event.target.value)}
            className="mt-2 w-full rounded-2xl border border-cyan-200/20 bg-slate-950/70 px-4 py-3 text-white outline-none focus:border-cyan-300/60"
          />
          <button
            type="button"
            onClick={onAnalyzeUpload}
            disabled={loading || !selectedFileName}
            className="mt-4 inline-flex items-center rounded-2xl border border-cyan-200/30 bg-cyan-400 px-4 py-2.5 text-sm font-semibold text-slate-950"
          >
            {loading ? "Analyzing..." : "Analyze uploaded file"}
          </button>
          <p className="mt-3 text-xs text-cyan-100/80">
            Selected: {selectedFileName || "No file selected"}
          </p>
        </div>

        <div className="home-option-card rounded-3xl border border-fuchsia-400/25 bg-fuchsia-500/10 p-5">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-fuchsia-100/80">
                Option 2: Calendar Replay
              </p>
              <p className="mt-2 text-sm text-fuchsia-50/80">
                Pick a date, choose a local log file, and load analysis directly
                from your system files.
              </p>
            </div>
            <button
              type="button"
              onClick={onRefreshCalendar}
              className="rounded-full border border-fuchsia-200/30 bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.14em] text-fuchsia-100"
            >
              {calendarLoading ? "Loading" : "Refresh"}
            </button>
          </div>

          <div className="calendar-shell mt-4 rounded-2xl border border-fuchsia-300/20 bg-slate-950/50 p-2 sm:p-3">
            <div className="mb-2 flex items-center justify-between gap-3 px-2">
              <p className="text-xs uppercase tracking-[0.16em] text-fuchsia-100/70">
                Select date from calendar
              </p>
              <span className="rounded-full border border-fuchsia-300/25 bg-fuchsia-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-fuchsia-100/80">
                {calendarRows.length} active dates
              </span>
            </div>
            <LocalizationProvider dateAdapter={AdapterDayjs}>
              <DateCalendar
                value={calendarValue}
                onChange={(newValue: Dayjs | null) =>
                  onCalendarDateChange(
                    newValue ? newValue.format("YYYY-MM-DD") : "",
                  )
                }
                showDaysOutsideCurrentMonth
                fixedWeekNumber={6}
                views={["year", "month", "day"]}
                sx={{
                  width: "100%",
                  bgcolor: "transparent",
                  color: isLight ? "#0f172a" : "#f8fafc",
                  "& .MuiDayCalendar-root": {
                    color: isLight ? "#0f172a" : "#f8fafc",
                  },
                  ".MuiTypography-root": {
                    color: isLight ? "#0f172a" : "#f8fafc",
                  },
                  "& .MuiDayCalendar-weekContainer .MuiPickersDay-root": {
                    color: isLight ? "#0f172a" : "#f8fafc",
                  },
                  ".MuiPickersCalendarHeader-root": {
                    px: 1,
                    pb: 1,
                    mb: 0.5,
                    borderBottom: isLight
                      ? "1px solid rgba(190,24,93,0.24)"
                      : "1px solid rgba(244,114,182,0.16)",
                  },
                  ".MuiPickersCalendarHeader-label": {
                    color: isLight ? "#831843" : "#fce7f3",
                    fontWeight: 800,
                    letterSpacing: "0.06em",
                    textTransform: "uppercase",
                    fontSize: "0.76rem",
                  },
                  ".MuiIconButton-root": {
                    color: isLight ? "#9d174d" : "#f0abfc",
                    border: isLight
                      ? "1px solid rgba(190,24,93,0.34)"
                      : "1px solid rgba(244,114,182,0.22)",
                    borderRadius: "10px",
                    backgroundColor: isLight
                      ? "rgba(255,255,255,0.78)"
                      : "rgba(15, 23, 42, 0.35)",
                  },
                  ".MuiDayCalendar-weekDayLabel": {
                    color: isLight ? "#9d174d" : "#fbcfe8",
                    fontWeight: 900,
                    fontSize: "0.84rem",
                    letterSpacing: "0.07em",
                  },
                  "& .MuiDayCalendar-weekDayLabel, & .MuiPickersCalendarHeader-label":
                    {
                      color: isLight ? "#9d174d" : "#f8fafc",
                    },
                  ".MuiPickersDay-root": {
                    color: isLight ? "#0f172a" : "#f8fafc",
                    borderRadius: "11px",
                    border: isLight
                      ? "1px solid rgba(51,65,85,0.18)"
                      : "1px solid rgba(148,163,184,0.16)",
                    backgroundColor: isLight
                      ? "rgba(255, 255, 255, 0.76)"
                      : "rgba(15, 23, 42, 0.25)",
                    transition:
                      "transform 160ms ease, background-color 160ms ease, border-color 160ms ease",
                  },
                  ".MuiPickersDay-root.Mui-disabled": {
                    color: isLight
                      ? "rgba(100,116,139,0.4)"
                      : "rgba(226, 232, 240, 0.45)",
                    borderColor: isLight
                      ? "rgba(100,116,139,0.14)"
                      : "rgba(148,163,184,0.08)",
                  },
                  "& .MuiPickersDay-dayOutsideMonth": {
                    color: isLight
                      ? "rgba(100,116,139,0.55)"
                      : "rgba(226,232,240,0.7)",
                  },
                  ".MuiPickersDay-root:not(.Mui-disabled):hover": {
                    transform: "translateY(-1px)",
                    borderColor: isLight
                      ? "rgba(190, 24, 93, 0.62)"
                      : "rgba(244, 114, 182, 0.65)",
                    backgroundColor: isLight
                      ? "rgba(251, 207, 232, 0.65)"
                      : "rgba(244, 114, 182, 0.2)",
                  },
                  ".MuiPickersDay-root.MuiPickersDay-today": {
                    borderColor: isLight
                      ? "rgba(14,165,233,0.75)"
                      : "rgba(56,189,248,0.7)",
                    backgroundColor: isLight
                      ? "rgba(14,165,233,0.16)"
                      : "rgba(56,189,248,0.14)",
                  },
                  ".MuiPickersDay-root.Mui-selected": {
                    backgroundColor: "#be185d",
                    color: "#ffffff",
                    fontWeight: 800,
                    boxShadow: "0 0 0 2px rgba(249,168,212,0.35)",
                  },
                  ".MuiPickersDay-root.Mui-selected:hover": {
                    backgroundColor: "#db2777",
                    color: "#ffffff",
                  },
                }}
              />
            </LocalizationProvider>
            <div className="px-2 pb-1 pt-1">
              <p className="text-xs text-fuchsia-100/70">
                Select any date. Files list appears when logs exist for that
                day.
              </p>
              {calendarDate ? (
                <p className="mt-1 text-xs font-semibold uppercase tracking-[0.14em] text-fuchsia-100/90">
                  Selected date: {dayjs(calendarDate).format("DD MMM YYYY")}
                </p>
              ) : null}
            </div>
          </div>

          {calendarDate ? (
            <div className="mt-4 rounded-2xl border border-fuchsia-300/20 bg-white/5 p-3">
              <p className="text-xs uppercase tracking-[0.16em] text-fuchsia-100/70">
                Available files on {calendarDate}
              </p>
              {availableCalendarFiles.length > 0 ? (
                <div className="mt-3">
                  <AnimatedList
                    items={availableCalendarFiles.map((file) => file.filename)}
                    selectedIndex={selectedCalendarIndex}
                    onItemSelect={(_, index) =>
                      onCalendarFileChange(
                        availableCalendarFiles[index]?.filename ?? "",
                      )
                    }
                    showGradients
                    enableArrowNavigation
                    displayScrollbar
                    renderItem={(item, index, selected) => {
                      const file = availableCalendarFiles[index];
                      return (
                        <div
                          className={`w-full rounded-xl border px-3 py-2 text-left text-sm transition ${
                            selected
                              ? "border-fuchsia-300/45 bg-fuchsia-400/20 text-white"
                              : "border-white/10 bg-slate-950/40 text-slate-200 hover:border-fuchsia-300/30"
                          }`}
                        >
                          <p className="font-semibold">{item}</p>
                          {file ? (
                            <p className="text-xs text-slate-300">
                              {formatBytes(file.size_bytes)} •{" "}
                              {formatDate(file.modified_at)}
                            </p>
                          ) : null}
                        </div>
                      );
                    }}
                  />
                </div>
              ) : (
                <p className="mt-3 text-sm text-slate-300">
                  No local logs found for this date.
                </p>
              )}
            </div>
          ) : null}

          <button
            type="button"
            onClick={onAnalyzeLocal}
            disabled={loading || !calendarFile}
            className="mt-4 inline-flex items-center rounded-2xl border border-fuchsia-200/30 bg-fuchsia-400 px-4 py-2.5 text-sm font-semibold text-slate-950 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-300"
          >
            Analyze selected local file
          </button>
          {calendarFile ? (
            <p className="mt-2 text-xs text-fuchsia-100/80">
              Selected file: {calendarFile}
            </p>
          ) : null}
        </div>
      </div>
    </section>
  );
}

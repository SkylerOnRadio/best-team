import type { ChangeEvent } from "react";
import Badge from "./Badge";

export default function UploadCard({
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

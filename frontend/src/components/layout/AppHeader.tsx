import ThemeToggle from "../home/ThemeToggle";

export default function AppHeader({
  theme,
  onToggleTheme,
  onAnalyzeUpload,
  analyzeDisabled,
  analyzeLabel = "Analyze upload",
}: {
  theme: "dark" | "light";
  onToggleTheme: () => void;
  onAnalyzeUpload: () => void;
  analyzeDisabled?: boolean;
  analyzeLabel?: string;
}) {
  return (
    <header className="app-header sticky top-0 z-20 border-b border-white/8 bg-slate-950/65 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:px-8">
        <div>
          <p className="font-display text-lg font-bold tracking-wide text-white sm:text-xl">
            Log Detector and Foreign Threat Analysis
          </p>
          <p className="text-xs uppercase tracking-[0.28em] text-slate-400">
            Home, manual scans, calendar replay, and forensic dashboard
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <button
            type="button"
            onClick={onAnalyzeUpload}
            disabled={analyzeDisabled}
            className="rounded-full border border-cyan-300/25 bg-cyan-400 px-3.5 py-2 text-xs font-semibold uppercase tracking-[0.14em] text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-300"
          >
            {analyzeLabel}
          </button>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </div>
      </div>
    </header>
  );
}

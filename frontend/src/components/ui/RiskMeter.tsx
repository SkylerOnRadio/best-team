import Badge from "./Badge";
import CountUp from "../CountUp";

function getRiskTone(score: number) {
  if (score >= 75) return "from-rose-500 to-rose-400";
  if (score >= 40) return "from-amber-500 to-orange-400";
  return "from-emerald-500 to-teal-400";
}

export default function RiskMeter({ score }: { score: number }) {
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
              <CountUp to={score} duration={1.2} separator="," startWhen />%
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

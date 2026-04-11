#!/usr/bin/env python3
"""
Evidence Protector – Automated Log Integrity & Behavioral Monitor
Detects gaps, out-of-order logs, and 'low-and-slow' attacker patterns.
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Optional, Dict, List

# ── ANSI colour codes ────────────────────────────────────────────────────────
USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

class C:
    RESET  = "\033[0m"   if USE_COLOUR else ""
    BOLD   = "\033[1m"   if USE_COLOUR else ""
    RED    = "\033[91m"  if USE_COLOUR else ""
    YELLOW = "\033[93m"  if USE_COLOUR else ""
    CYAN   = "\033[96m"  if USE_COLOUR else ""
    GREEN  = "\033[92m"  if USE_COLOUR else ""
    GREY   = "\033[90m"  if USE_COLOUR else ""
    DIM    = "\033[2m"   if USE_COLOUR else ""

# ── Extraction Patterns ──────────────────────────────────────────────────────
TIMESTAMP_PATTERNS = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]),
    (r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}", ["%d/%b/%Y:%H:%M:%S"]),
    (r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]),
    (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", ["%Y-%m-%d %H:%M:%S"]),
    (r"\b1[0-9]{9}\b", None),
]

IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
ATTACK_KEYWORDS = {
    "BRUTE_FORCE": [r"failed", r"invalid user", r"authentication failure", r"password"],
    "SCANNING":    [r"nmap", r"scan", r"probe", r"port"],
    "PING":        [r"icmp", r"echo request", r"ping"],
    "UNUSUAL":     [r"proxy", r"tor", r"vpn", r"tunnel"]
}

CURRENT_YEAR = datetime.now().year

# ── Helper Functions ────────────────────────────────────────────────────────
def _strip_tz(raw: str) -> str:
    return re.sub(r"(?:Z|[+-]\d{2}:?\d{2})$", "", raw).strip()

def parse_timestamp(line: str) -> Optional[datetime]:
    for pattern, fmts in TIMESTAMP_PATTERNS:
        m = re.search(pattern, line)
        if not m: continue
        raw = m.group()
        if fmts is None:
            try: return datetime.utcfromtimestamp(int(raw))
            except: continue
        clean = _strip_tz(raw)
        for fmt in fmts:
            try:
                dt = datetime.strptime(clean, fmt)
                if dt.year == 1900: dt = dt.replace(year=CURRENT_YEAR)
                return dt
            except ValueError: continue
    return None

def detect_activity(line: str) -> List[str]:
    tags = []
    lower_line = line.lower()
    for category, patterns in ATTACK_KEYWORDS.items():
        if any(re.search(p, lower_line) for p in patterns):
            tags.append(category)
    return tags

def classify_gap(seconds: float) -> tuple[str, str]:
    if seconds < 0: return "REVERSED", C.RED
    if seconds >= 3600: return "CRITICAL", C.RED
    if seconds >= 600: return "HIGH", C.YELLOW
    if seconds >= 60: return "MEDIUM", C.CYAN
    return "LOW", C.GREEN

def _human_duration(seconds: float) -> str:
    seconds = abs(int(seconds))
    if seconds < 60: return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600)
    return f"{h}h {rem // 60}m"

def _risk_score(gaps: list, threats: list) -> int:
    if not gaps and not threats: return 0
    severities = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "REVERSED": 50}
    raw_gaps = sum(severities.get(g["severity"], 0) for g in gaps)
    raw_threats = len(threats) * 15
    return min(raw_gaps + raw_threats, 100)

def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

# ── Core Analysis Engine ─────────────────────────────────────────────────────
def scan_log(filepath: str, threshold_seconds: float):
    gaps, total_lines, parsed_lines, skipped_lines = [], 0, 0, 0
    prev_ts, prev_line_no, first_ts, last_ts = None, 0, None, None
    ip_stats = {} 

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                total_lines += 1
                line_content = line.rstrip("\n")
                ts = parse_timestamp(line_content)

                if ts is None:
                    skipped_lines += 1
                    continue

                parsed_lines += 1
                if first_ts is None: first_ts = ts
                last_ts = ts

                if prev_ts is not None:
                    delta = (ts - prev_ts).total_seconds()
                    if delta >= threshold_seconds or delta < 0:
                        label, _ = classify_gap(delta)
                        gaps.append({
                            "type": "REVERSED" if delta < 0 else "GAP",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end": ts.isoformat(),
                            "duration_sec": round(delta, 2),
                            "duration_human": _human_duration(delta),
                            "severity": label,
                            "start_line": prev_line_no,
                            "end_line": line_no,
                        })

                ip_match = re.search(IP_PATTERN, line_content)
                if ip_match:
                    ip = ip_match.group()
                    tags = detect_activity(line_content)
                    if ip not in ip_stats:
                        ip_stats[ip] = {"first_seen": ts, "last_seen": ts, "tags": set(), "hits": 0}
                    ip_stats[ip]["last_seen"] = ts
                    ip_stats[ip]["hits"] += 1
                    for t in tags: ip_stats[ip]["tags"].add(t)

                prev_ts, prev_line_no = ts, line_no

    except Exception as e:
        print(f"File Access Error: {e}", file=sys.stderr)
        sys.exit(1)

    threats = []
    for ip, data in ip_stats.items():
        span = (data["last_seen"] - data["first_seen"]).total_seconds()
        if span > 86400 * 2: data["tags"].add("PERSISTENT_ACTOR")
        if len(data["tags"]) > 0 or data["hits"] > 100:
            threats.append({
                "ip": ip,
                "risk_tags": list(data["tags"]),
                "hits": data["hits"],
                "span_human": _human_duration(span),
                "last_active": data["last_seen"].isoformat()
            })

    return {
        "gaps": gaps,
        "threats": threats,
        "stats": {
            "total_lines": total_lines,
            "parsed_lines": parsed_lines,
            "skipped_lines": skipped_lines,
            "log_span_sec": (last_ts - first_ts).total_seconds() if first_ts else 0,
            "first_ts": first_ts,
            "last_ts": last_ts
        }
    }

# ── Concised Terminal Reporter ────────────────────────────────────────────────
def report_terminal(result: dict, filepath: str, threshold: float):
    s = result["stats"]
    gaps = result["gaps"]
    threats = result["threats"]
    risk = _risk_score(gaps, threats)
    risk_col = C.RED if risk >= 60 else (C.YELLOW if risk >= 30 else C.GREEN)
    
    total_sec = s["log_span_sec"]
    density = (s["parsed_lines"] / (total_sec / 60)) if total_sec > 0 else 0
    
    print(f"\n{C.BOLD}{'─'*75}{C.RESET}")
    print(f"{C.BOLD}  🛡️  EVIDENCE PROTECTOR – High-Level Forensic Summary{C.RESET}")
    print(f"{'─'*75}")
    print(f"  Target File : {C.CYAN}{filepath}{C.RESET}")
    print(f"  Log Span    : {_human_duration(total_sec)}")
    print(f"  Integrity   : {s['parsed_lines']:,} parsed  |  {C.GREY}{s['skipped_lines']:,} skipped{C.RESET}")
    print(f"  Density     : {density:.2f} events/min")
    print()

    print(f"  Risk Score  : {risk_col}{C.BOLD}{risk:>3}/100{C.RESET}  "
          f"{risk_col}{_bar(risk, 100)}{C.RESET}")
    print(f"{'─'*75}")

    print(f"\n  {C.BOLD}[🚨 ANOMALY SUMMARY]{C.RESET}")
    print(f"    Timeline Gaps : {C.YELLOW if gaps else C.GREEN}{len(gaps)}{C.RESET}")
    print(f"    Threat Actors : {C.RED if threats else C.GREEN}{len(threats)}{C.RESET}")
    
    print(f"\n  {C.CYAN}Notice:{C.RESET} Detailed tables and anomaly lists have been exported to:")
    print(f"  - {C.BOLD}report.json{C.RESET} (Updated state)")
    print(f"  - {C.BOLD}reportN.csv{C.RESET} (Historical evidence)")
    print(f"  - {C.BOLD}forensic_report_TIMESTAMP.html{C.RESET} (Visual evidence)")
    print(f"{'─'*75}\n")

# ── CSV Export (Incrementing Filename) ──────────────────────────────────────
def report_csv(result: dict):
    i = 1
    while os.path.exists(f"report{i}.csv"):
        i += 1
    file_path = f"report{i}.csv"
    
    fields = ["type", "gap_start", "gap_end", "duration_sec", "duration_human", "severity", "start_line", "end_line"]
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["gaps"])
    print(f"[*] Detailed CSV generated → {file_path}")

# ── JSON Export (Updated Everytime) ──────────────────────────────────────────
def report_json(result: dict, output_path: str = "report.json"):
    clean_result = result.copy()
    if clean_result["stats"]["first_ts"]: clean_result["stats"]["first_ts"] = clean_result["stats"]["first_ts"].isoformat()
    if clean_result["stats"]["last_ts"]: clean_result["stats"]["last_ts"] = clean_result["stats"]["last_ts"].isoformat()
    with open(output_path, "w") as fh:
        json.dump(clean_result, fh, indent=2)
    print(f"[*] JSON state updated → {output_path}")

# ── HTML Export (Detailed Visual Report) ─────────────────────────────────────
def report_html(result: dict, filepath: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"forensic_report_{timestamp}.html"
    risk = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 60 else ("#f59e0b" if risk >= 30 else "#10b981")
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f3f4f6; color: #1f2937; padding: 40px; line-height: 1.5; }}
            .card {{ background: white; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.05); padding: 24px; margin-bottom: 24px; border: 1px solid #e5e7eb; }}
            h1, h2 {{ color: #111827; margin-top: 0; }}
            .risk-meter {{ height: 24px; background: #e5e7eb; border-radius: 12px; overflow: hidden; margin: 15px 0; }}
            .risk-fill {{ height: 100%; background: {risk_color}; width: {risk}% }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; border-radius: 8px; overflow: hidden; }}
            th, td {{ text-align: left; padding: 14px; border-bottom: 1px solid #f3f4f6; }}
            th {{ background: #f9fafb; font-weight: 600; text-transform: uppercase; font-size: 12px; color: #6b7280; letter-spacing: 0.05em; }}
            tr:hover {{ background: #f9fafb; }}
            .tag {{ padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
            .tag-red {{ background: #fee2e2; color: #991b1b; }}
            .tag-blue {{ background: #dbeafe; color: #1e40af; }}
            .tag-yellow {{ background: #fef3c7; color: #92400e; }}
        </style>
        <title>Detailed Forensic Report - {filepath}</title>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ Evidence Protector Detailed Analysis</h1>
            <p style="margin: 0; color: #6b7280;">Forensic audit for: <strong>{filepath}</strong></p>
            <div style="margin-top: 20px;">
                <strong>System Risk Score: {risk}/100</strong>
                <div class="risk-meter"><div class="risk-fill"></div></div>
            </div>
        </div>
        
        <div class="card">
            <h2>⏳ Detected Timeline Anomalies</h2>
            <p>Full list of gaps and reversals detected during the scan.</p>
            <table>
                <thead><tr><th>#</th><th>Type</th><th>Severity</th><th>Duration</th><th>Window</th><th>Lines</th></tr></thead>
                <tbody>
                    {"".join([f"<tr><td>{i}</td><td><span class='tag tag-red'>{g['type']}</span></td><td>{g['severity']}</td><td>{g['duration_human']}</td><td>{g['gap_start'][:19]} -> {g['gap_end'][:19]}</td><td>{g['start_line']} - {g['end_line']}</td></tr>" for i, g in enumerate(result['gaps'], 1)])}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>💀 Threat Intelligence (IP Patterns)</h2>
            <p>Entities showing suspicious behavioral patterns across the timeline.</p>
            <table>
                <thead><tr><th>IP Address</th><th>Hits</th><th>Span</th><th>Risk Indicators</th></tr></thead>
                <tbody>
                    {"".join([f"<tr><td><strong>{t['ip']}</strong></td><td>{t['hits']}</td><td>{t['span_human']}</td><td>{' '.join([f'<span class="tag tag-blue">{tag}</span>' for tag in t['risk_tags']])}</td></tr>" for t in result['threats']])}
                </tbody>
            </table>
        </div>
        <footer style="text-align: center; color: #9ca3af; font-size: 12px; margin-top: 40px;">
            Generated by Evidence Protector Engine v2.1
        </footer>
    </body>
    </html>
    """
    with open(out_file, "w") as f:
        f.write(html)
    print(f"[*] Visual HTML report generated → {out_file}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["all", "terminal", "json", "csv", "html"], default="all")
    p.add_argument("--out", "-o", help="Specific JSON output path (defaults to report.json)")
    args = p.parse_args()

    if not os.path.isfile(args.logfile): sys.exit(1)
    res = scan_log(args.logfile, args.threshold)
    
    # Run reports based on the requested format
    # In 'all' mode (default), we generate terminal summary, update report.json,
    # increment reportN.csv, and generate a new detailed HTML.
    
    if args.format in ("all", "terminal"):
        report_terminal(res, args.logfile, args.threshold)
    
    if args.format in ("all", "csv"):
        report_csv(res)
        
    if args.format in ("all", "html"):
        report_html(res, args.logfile)
        
    if args.format in ("all", "json"):
        out = args.out if args.out else "report.json"
        report_json(res, out)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Evidence Protector v2.5 – Universal Log Integrity & Behavioral Monitor
Detects gaps, out-of-order logs, and 'low-and-slow' attacker patterns across 
Linux, Windows, Web, and Network log formats.
"""

import argparse
import csv
import json
import os
import re
import sys
import platform
import time
import socket
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

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

# ── Enhanced Universal Timestamp patterns ────────────────────────────────────
TIMESTAMP_PATTERNS = [
    # ISO 8601 (Web/Cloud)
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"], "ISO-8601"),
    # Apache Common / Nginx
    (r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]", ["[%d/%b/%Y:%H:%M:%S %z]"], "Web (Apache/Nginx)"),
    # Syslog (RFC3164)
    (r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
     ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"], "Linux Syslog"),
    # Windows Event Log (Standard)
    (r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", ["%Y/%m/%d %H:%M:%S"], "Windows Event"),
    # Cisco / Network Hardware
    (r"\d{2}:\d{2}:\d{2}\.\d+ \w{3} \w{3} \d{2} \d{4}", ["%H:%M:%S.%f %Z %a %b %d %Y"], "Network (Cisco)"),
    # Unix Epoch
    (r"\b1[0-9]{9}\b", None, "Unix Epoch"),
    # Common US format
    (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", ["%m/%d/%Y %H:%M:%S"], "Generic (MM/DD/YYYY)"),
]

IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
ATTACK_KEYWORDS = {
    "BRUTE_FORCE": [r"failed", r"invalid user", r"auth fail", r"password", r"denied"],
    "SCANNING":    [r"nmap", r"scan", r"probe", r"port", r"sqli", r"xss"],
    "PING":        [r"icmp", r"echo request", r"ping", r"unreachable"],
    "UNUSUAL":     [r"proxy", r"tor", r"vpn", r"tunnel", r"hidden", r"suspicious"]
}

CURRENT_YEAR = datetime.now().year

# ── Helper Utilities ─────────────────────────────────────────────────────────
def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    """Generates a visual progress bar string."""
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

def _risk_score(gaps: list, threats: list) -> int:
    """Return 0-100 composite risk score."""
    if not gaps and not threats: return 0
    raw = sum({"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2, "REVERSED": 50}.get(g["severity"], 0) for g in gaps)
    raw += len(threats) * 15
    return min(raw, 100)

def _human_duration(seconds: float) -> str:
    """Converts seconds into a human readable string."""
    seconds = abs(int(seconds))
    if seconds < 60: return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600)
    return f"{h}h {rem // 60}m"

# ── Metadata Gathering ───────────────────────────────────────────────────────
def get_system_metadata() -> Dict:
    return {
        "os_type": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "scan_timestamp": datetime.now().isoformat()
    }

def get_file_metadata(filepath: str) -> Dict:
    stats = os.stat(filepath)
    return {
        "filename": os.path.basename(filepath),
        "path": os.path.abspath(filepath),
        "size_bytes": stats.st_size,
        "created_at": datetime.fromtimestamp(stats.st_ctime).isoformat(),
        "modified_at": datetime.fromtimestamp(stats.st_mtime).isoformat(),
        "extension": os.path.splitext(filepath)[1]
    }

# ── Parsing Helpers ──────────────────────────────────────────────────────────
def _strip_tz(raw: str) -> str:
    # Handle timezone brackets [01/Jan/2024...]
    raw = raw.strip("[]")
    return re.sub(r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$", "", raw).strip()

def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    for pattern, fmts, label in TIMESTAMP_PATTERNS:
        m = re.search(pattern, line)
        if not m: continue
        raw = m.group()
        
        if fmts is None: # Unix Epoch
            try: return datetime.fromtimestamp(int(raw), tz=None), label
            except: continue
            
        clean = _strip_tz(raw)
        for fmt in fmts:
            try:
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = datetime.strptime(f"{CURRENT_YEAR} {clean}", f"%Y {fmt}")
                else:
                    dt = datetime.strptime(clean, fmt)
                return dt, label
            except ValueError: continue
    return None, None

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

# ── Core Analysis Engine ─────────────────────────────────────────────────────
def scan_log(filepath: str, threshold_seconds: float):
    start_time = time.time()
    gaps, total_lines, parsed_lines, skipped_lines = [], 0, 0, 0
    prev_ts, prev_line_no, first_ts, last_ts = None, 0, None, None
    log_type_counts = {}
    ip_stats = {} 

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                total_lines += 1
                line_content = line.rstrip("\n")
                ts, ltype = parse_timestamp(line_content)

                if ts is None:
                    skipped_lines += 1
                    continue

                parsed_lines += 1
                log_type_counts[ltype] = log_type_counts.get(ltype, 0) + 1
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

    processing_time = time.time() - start_time
    detected_log_type = max(log_type_counts, key=log_type_counts.get) if log_type_counts else "Unknown"

    return {
        "gaps": gaps,
        "threats": threats,
        "system_info": get_system_metadata(),
        "file_info": get_file_metadata(filepath),
        "performance": {
            "processing_time_sec": round(processing_time, 4),
            "lines_per_sec": round(total_lines / processing_time, 2) if processing_time > 0 else 0
        },
        "stats": {
            "log_type": detected_log_type,
            "total_lines": total_lines,
            "parsed_lines": parsed_lines,
            "skipped_lines": skipped_lines,
            "log_span_sec": (last_ts - first_ts).total_seconds() if first_ts else 0,
            "first_ts": first_ts,
            "last_ts": last_ts
        }
    }

# ── Reporting Functions ──────────────────────────────────────────────────────
def report_terminal(result: dict, filepath: str, threshold: float):
    s = result["stats"]
    f = result["file_info"]
    p = result["performance"]
    risk = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 60 else (C.YELLOW if risk >= 30 else C.GREEN)
    
    print(f"\n{C.BOLD}{'─'*75}{C.RESET}")
    print(f"{C.BOLD}  🛡️  EVIDENCE PROTECTOR v2.5 – Advanced Forensic Report{C.RESET}")
    print(f"{'─'*75}")
    print(f"  Target File : {C.CYAN}{f['filename']}{C.RESET} ({s['log_type']})")
    print(f"  System      : {result['system_info']['hostname']} ({result['system_info']['os_type']})")
    print(f"  Performance : {p['processing_time_sec']}s  |  {p['lines_per_sec']:,} lines/sec")
    print(f"  Log Span    : {_human_duration(s['log_span_sec'])}")
    
    print(f"\n  Risk Score  : {risk_col}{C.BOLD}{risk:>3}/100{C.RESET}  "
          f"{risk_col}{_bar(risk, 100)}{C.RESET}")
    print(f"{'─'*75}")

    print(f"\n  {C.BOLD}[🚨 ANOMALY SUMMARY]{C.RESET}")
    print(f"    Timeline Gaps : {C.YELLOW if result['gaps'] else C.GREEN}{len(result['gaps'])}{C.RESET}")
    print(f"    Threat Actors : {C.RED if result['threats'] else C.GREEN}{len(result['threats'])}{C.RESET}")
    
    print(f"\n  {C.CYAN}Notice:{C.RESET} Detailed evidence has been exported to:")
    print(f"  - {C.BOLD}report.json{C.RESET} (Full metadata & analysis)")
    print(f"  - {C.BOLD}reportN.csv{C.RESET} (Historical CSV data)")
    print(f"  - {C.BOLD}forensic_report_TIMESTAMP.html{C.RESET} (Full HTML evidence)")
    print(f"{'─'*75}\n")

def report_csv(result: dict):
    i = 1
    while os.path.exists(f"report{i}.csv"): i += 1
    file_path = f"report{i}.csv"
    fields = ["type", "gap_start", "gap_end", "duration_sec", "duration_human", "severity", "start_line", "end_line"]
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["gaps"])
    print(f"[*] Detailed CSV generated → {file_path}")

def report_json(result: dict, output_path: str = "report.json"):
    clean_result = result.copy()
    if clean_result["stats"]["first_ts"]: clean_result["stats"]["first_ts"] = clean_result["stats"]["first_ts"].isoformat()
    if clean_result["stats"]["last_ts"]: clean_result["stats"]["last_ts"] = clean_result["stats"]["last_ts"].isoformat()
    with open(output_path, "w") as fh:
        json.dump(clean_result, fh, indent=2)
    print(f"[*] JSON state updated → {output_path}")

def report_html(result: dict, filepath: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"forensic_report_{timestamp}.html"
    sys = result["system_info"]
    perf = result["performance"]
    stats = result["stats"]
    risk = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 60 else ("#f59e0b" if risk >= 30 else "#10b981")
    
    # Sort anomalies into categories for a cleaner UI
    gap_count = sum(1 for g in result['gaps'] if g['type'] == 'GAP')
    rev_count = sum(1 for g in result['gaps'] if g['type'] == 'REVERSED')
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {{
                --primary: #111827;
                --secondary: #4b5563;
                --danger: #ef4444;
                --warning: #f59e0b;
                --success: #10b981;
                --bg: #f3f4f6;
                --card-bg: #ffffff;
            }}
            body {{ font-family: 'Inter', -apple-system, sans-serif; background: var(--bg); color: var(--primary); padding: 20px; line-height: 1.6; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .card {{ background: var(--card-bg); border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; }}
            h1, h2, h3 {{ color: var(--primary); margin: 0 0 15px 0; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
            
            .risk-meter {{ height: 28px; background: #e5e7eb; border-radius: 14px; overflow: hidden; margin: 15px 0; position: relative; }}
            .risk-fill {{ height: 100%; background: {risk_color}; width: {risk}% }}
            .risk-text {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #fff; font-weight: bold; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }}
            
            details {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px; }}
            details[open] {{ padding-bottom: 10px; }}
            summary {{ padding: 15px; font-weight: 600; cursor: pointer; display: flex; align-items: center; list-style: none; }}
            summary::-webkit-details-marker {{ display: none; }}
            summary:after {{ content: '▶'; margin-left: auto; transition: transform 0.2s; font-size: 12px; }}
            details[open] summary:after {{ transform: rotate(90deg); }}
            summary:hover {{ background: #f3f4f6; }}
            
            table {{ width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 10px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e5e7eb; }}
            th {{ background: #f3f4f6; color: var(--secondary); font-size: 12px; text-transform: uppercase; }}
            
            .tag {{ padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
            .tag-red {{ background: #fee2e2; color: #991b1b; }}
            .tag-blue {{ background: #dbeafe; color: #1e40af; }}
            .tag-yellow {{ background: #fef3c7; color: #92400e; }}
            
            .metric {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px dashed #e5e7eb; }}
            .metric:last-child {{ border: none; }}
            .label {{ color: var(--secondary); font-size: 14px; }}
            .value {{ font-weight: 600; }}
        </style>
        <title>Forensic Evidence Report</title>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🛡️ Evidence Protector v2.5</h1>
                <p style="color: var(--secondary);">Integrity Audit: <strong>{os.path.basename(filepath)}</strong></p>
                <div class="risk-meter">
                    <div class="risk-fill"></div>
                    <span class="risk-text">RISK SCORE: {risk}/100</span>
                </div>
            </div>

            <div class="grid">
                <div class="card">
                    <h2>💻 System Context</h2>
                    <div class="metric"><span class="label">Hostname</span><span class="value">{sys['hostname']}</span></div>
                    <div class="metric"><span class="label">OS</span><span class="value">{sys['os_type']} ({sys['os_release']})</span></div>
                    <div class="metric"><span class="label">Architecture</span><span class="value">{sys['architecture']}</span></div>
                </div>
                <div class="card">
                    <h2>📊 Scan Metadata</h2>
                    <div class="metric"><span class="label">Log Type</span><span class="value">{stats['log_type']}</span></div>
                    <div class="metric"><span class="label">Processing Time</span><span class="value">{perf['processing_time_sec']}s</span></div>
                    <div class="metric"><span class="label">Throughput</span><span class="value">{perf['lines_per_sec']:,} L/s</span></div>
                </div>
            </div>

            <div class="card">
                <h2>📁 Category Overview</h2>
                
                <details>
                    <summary>Timeline Gaps ({gap_count})</summary>
                    <div style="padding: 0 15px;">
                        {"<p>No gaps detected.</p>" if gap_count == 0 else f"""
                        <table>
                            <thead><tr><th>Start</th><th>End</th><th>Duration</th><th>Severity</th></tr></thead>
                            <tbody>
                                {"".join([f"<tr><td>{g['gap_start'][:19]}</td><td>{g['gap_end'][:19]}</td><td>{g['duration_human']}</td><td><span class='tag tag-yellow'>{g['severity']}</span></td></tr>" for g in result['gaps'] if g['type'] == 'GAP'])}
                            </tbody>
                        </table>
                        """}
                    </div>
                </details>

                <details>
                    <summary>Time Reversals ({rev_count})</summary>
                    <div style="padding: 0 15px;">
                        {"<p>No reversals detected.</p>" if rev_count == 0 else f"""
                        <table>
                            <thead><tr><th>Current Line</th><th>Previous TS</th><th>Current TS</th></tr></thead>
                            <tbody>
                                {"".join([f"<tr><td>{g['end_line']}</td><td>{g['gap_start'][:19]}</td><td>{g['gap_end'][:19]}</td></tr>" for g in result['gaps'] if g['type'] == 'REVERSED'])}
                            </tbody>
                        </table>
                        """}
                    </div>
                </details>

                <details>
                    <summary>Threat Actors ({len(result['threats'])})</summary>
                    <div style="padding: 0 15px;">
                        {"<p>No threat actors identified.</p>" if not result['threats'] else f"""
                        <table>
                            <thead><tr><th>IP Address</th><th>Hits</th><th>Span</th><th>Tags</th></tr></thead>
                            <tbody>
                                {"".join([f"<tr><td><strong>{t['ip']}</strong></td><td>{t['hits']}</td><td>{t['span_human']}</td><td>{' '.join([f'<span class="tag tag-blue">{tag}</span>' for tag in t['risk_tags']])}</td></tr>" for t in result['threats']])}
                            </tbody>
                        </table>
                        """}
                    </div>
                </details>

                <details>
                    <summary>Show All Raw Anomalies ({len(result['gaps'])})</summary>
                    <div style="padding: 0 15px;">
                        <table>
                            <thead><tr><th>Type</th><th>Duration</th><th>Window</th><th>Lines</th></tr></thead>
                            <tbody>
                                {"".join([f"<tr><td><span class='tag tag-red'>{g['type']}</span></td><td>{g['duration_human']}</td><td>{g['gap_start'][:19]} -> {g['gap_end'][:19]}</td><td>{g['start_line']} - {g['end_line']}</td></tr>" for g in result['gaps']])}
                            </tbody>
                        </table>
                    </div>
                </details>
            </div>
            
            <footer style="text-align: center; color: var(--secondary); font-size: 12px; margin-top: 20px;">
                Evidence Protector Engine v2.5 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </footer>
        </div>
    </body>
    </html>
    """
    with open(out_file, "w") as f: f.write(html)
    print(f"[*] Structured HTML report generated → {out_file}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["all", "terminal", "json", "csv", "html"], default="all")
    p.add_argument("--out", "-o", help="Specific JSON path")
    args = p.parse_args()

    if not os.path.isfile(args.logfile): 
        print(f"Error: {args.logfile} is not a valid file.")
        sys.exit(1)
        
    res = scan_log(args.logfile, args.threshold)
    
    if args.format in ("all", "terminal"): report_terminal(res, args.logfile, args.threshold)
    if args.format in ("all", "csv"): report_csv(res)
    if args.format in ("all", "html"): report_html(res, args.logfile)
    if args.format in ("all", "json"): report_json(res, args.out if args.out else "report.json")

if __name__ == "__main__":
    main()
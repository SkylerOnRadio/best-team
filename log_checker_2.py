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
    """Return 0-100 composite risk score."""
    if not gaps and not threats:
        return 0
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

# ── Detailed Terminal Reporter ────────────────────────────────────────────────
def report_terminal(result: dict, filepath: str, threshold: float):
    s = result["stats"]
    gaps = result["gaps"]
    threats = result["threats"]
    risk = _risk_score(gaps, threats)
    risk_col = C.RED if risk >= 60 else (C.YELLOW if risk >= 30 else C.GREEN)
    
    total_sec = s["log_span_sec"]
    density = (s["parsed_lines"] / (total_sec / 60)) if total_sec > 0 else 0
    
    print(f"\n{C.BOLD}{'─'*75}{C.RESET}")
    print(f"{C.BOLD}  EVIDENCE PROTECTOR v2.0  –  Forensic & Behavioral Integrity Report{C.RESET}")
    print(f"{'─'*75}")
    print(f"  File      : {C.CYAN}{filepath}{C.RESET}")
    print(f"  Threshold : {threshold}s  ({_human_duration(threshold)})")
    print(f"  Log Span  : {_human_duration(total_sec)}")
    if s["first_ts"]:
        print(f"  Timeline  : {s['first_ts'].isoformat()}  ->  {s['last_ts'].isoformat()}")
    print()
    print(f"  Lines     : {s['total_lines']:,} total  |  "
          f"{s['parsed_lines']:,} parsed  |  "
          f"{C.GREY}{s['skipped_lines']:,} skipped{C.RESET}")
    print(f"  Density   : {density:.2f} events/min")
    print()

    # Risk Section
    print(f"  Risk score: {risk_col}{C.BOLD}{risk:>3}/100{C.RESET}  "
          f"{risk_col}{_bar(risk, 100)}{C.RESET}")
    print(f"{'─'*75}")

    # Gap Section
    print(f"\n  {C.BOLD}[⏳ TIMELINE ANOMALIES]{C.RESET}")
    if not gaps:
        print(f"    {C.GREEN}No suspicious gaps or reversals detected.{C.RESET}")
    else:
        # Severity breakdown
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "REVERSED": 0}
        for g in gaps: counts[g["severity"]] = counts.get(g["severity"], 0) + 1
        
        for sev, col in [("CRITICAL", C.RED), ("HIGH", C.YELLOW), ("REVERSED", C.RED)]:
            if counts[sev]:
                print(f"    {col}{sev:<10}{C.RESET} {counts[sev]:>2}  {col}{_bar(counts[sev], len(gaps), 20)}{C.RESET}")

        print(f"\n  {'#':<4} {'TYPE':<10} {'DURATION':<12} {'START TIMESTAMP':<20} {'LINE':>5}")
        print(f"  {'─'*4} {'─'*10} {'─'*12} {'─'*20} {'─'*5}")
        for i, g in enumerate(gaps[:10], start=1):
            _, col = classify_gap(g["duration_sec"] if g["type"] != "REVERSED" else -1)
            print(f"  {i:<4} {col+g['type']:<20} {g['duration_human']:<12} {g['gap_start'][:19]:<20} {g['start_line']:>5}")
        if len(gaps) > 10: print(f"  ... and {len(gaps)-10} more anomalies")

    # Threat Intelligence Section
    print(f"\n  {C.BOLD}[💀 THREAT INTELLIGENCE]{C.RESET}")
    if not threats:
        print(f"    {C.GREEN}No suspicious IP patterns identified.{C.RESET}")
    else:
        print(f"  {'IP ADDRESS':<16} {'HITS':<6} {'SPAN':<10} {'RISK TAGS'}")
        print(f"  {'─'*16} {'─'*6} {'─'*10} {'─'*30}")
        for t in sorted(threats, key=lambda x: x['hits'], reverse=True)[:5]:
            tags_str = ", ".join(t['risk_tags'])
            print(f"  {C.BOLD}{t['ip']:<16}{C.RESET} {t['hits']:<6} {t['span_human']:<10} {C.RED}{tags_str}{C.RESET}")

    # Forensic Callout
    if gaps:
        worst = max(gaps, key=lambda g: g["duration_sec"])
        _, wcol = classify_gap(worst["duration_sec"])
        print(f"\n{'─'*75}")
        print(f"  {C.BOLD}Primary Evidence Gap:{C.RESET}")
        print(f"    Range  : {worst['gap_start']} --> {worst['gap_end']}")
        print(f"    Impact : {wcol}{C.BOLD}{worst['duration_human']}{C.RESET} missing (Lines {worst['start_line']}–{worst['end_line']})")
    print(f"{'─'*75}\n")

def report_json(result: dict, output_path: str):
    # Ensure datetime objects are converted to strings for JSON
    clean_result = result.copy()
    if clean_result["stats"]["first_ts"]: clean_result["stats"]["first_ts"] = clean_result["stats"]["first_ts"].isoformat()
    if clean_result["stats"]["last_ts"]: clean_result["stats"]["last_ts"] = clean_result["stats"]["last_ts"].isoformat()
    with open(output_path, "w") as fh:
        json.dump(clean_result, fh, indent=2)
    print(f"[*] JSON forensic data saved to {output_path}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["terminal", "json"], default="terminal")
    p.add_argument("--out", "-o", help="Output file for JSON")
    args = p.parse_args()

    if not os.path.isfile(args.logfile): sys.exit(1)
    res = scan_log(args.logfile, args.threshold)
    
    if args.format == "terminal":
        report_terminal(res, args.logfile, args.threshold)
    else:
        if not args.out: 
            print("Error: --out required for JSON format")
            return
        report_json(res, args.out)

if __name__ == "__main__":
    main()
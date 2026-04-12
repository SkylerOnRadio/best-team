#!/usr/bin/env python3
"""
Evidence Protector – Automated Log Integrity Monitor
Scans log files for suspicious time gaps that may indicate tampering.
Usage: python evidence_protector.py <logfile> [options]
"""

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timedelta
from typing import Optional

# ── ANSI colour codes (gracefully disabled on Windows / non-TTY) ──────────────
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

# ── Timestamp patterns (ordered most-specific first) ─────────────────────────
TIMESTAMP_PATTERNS = [
    # ISO 8601 / RFC 3339  2024-01-15T14:30:05.123Z or +05:30
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
      "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]),
    # syslog / Apache common  Jan 15 14:30:05  or  15/Jan/2024:14:30:05 +0530
    (r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
     ["%d/%b/%Y:%H:%M:%S"]),
    # syslog without year  Jan 15 14:30:05
    (r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
     ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]),
    # Windows event log  2024-01-15 14:30:05
    (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
     ["%Y-%m-%d %H:%M:%S"]),
    # Unix epoch (bare integer 10-digit)
    (r"\b1[0-9]{9}\b", None),
    # MM/DD/YYYY HH:MM:SS
    (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
     ["%m/%d/%Y %H:%M:%S"]),
]

CURRENT_YEAR = datetime.now().year


def _strip_tz(raw: str) -> str:
    """Remove timezone suffix so strptime doesn't choke."""
    return re.sub(r"(?:Z|[+-]\d{2}:?\d{2})$", "", raw).strip()


def parse_timestamp(line: str) -> Optional[datetime]:
    """Return the first parseable datetime found in *line*, or None."""
    for pattern, fmts in TIMESTAMP_PATTERNS:
        m = re.search(pattern, line)
        if not m:
            continue
        raw = m.group()

        # Unix epoch
        if fmts is None:
            try:
                return datetime.utcfromtimestamp(int(raw))
            except (ValueError, OSError):
                continue

        clean = _strip_tz(raw)
        for fmt in fmts:
            try:
                dt = datetime.strptime(clean, fmt)
                # Patch missing year (syslog)
                if dt.year == 1900:
                    dt = dt.replace(year=CURRENT_YEAR)
                return dt
            except ValueError:
                continue
    return None


# ── Gap severity classification ───────────────────────────────────────────────
def classify_gap(seconds: float) -> tuple[str, str]:
    """Return (label, colour) based on gap duration."""
    if seconds >= 3600:
        return "CRITICAL", C.RED
    if seconds >= 600:
        return "HIGH    ", C.YELLOW
    if seconds >= 60:
        return "MEDIUM  ", C.CYAN
    return "LOW     ", C.GREEN


# ── Core scanner ─────────────────────────────────────────────────────────────
def scan_log(filepath: str, threshold_seconds: float, quiet: bool = False):
    """
    Parse *filepath* line by line.

    Returns a dict with keys:
        gaps            list of gap dicts
        total_lines     int
        parsed_lines    int
        skipped_lines   int
        first_ts        datetime | None
        last_ts         datetime | None
        log_span        timedelta | None
    """
    gaps = []
    total_lines = 0
    parsed_lines = 0
    skipped_lines = 0
    prev_ts: Optional[datetime] = None
    prev_line_no = 0
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                total_lines += 1
                line = line.rstrip("\n")

                ts = parse_timestamp(line)

                if ts is None:
                    skipped_lines += 1
                    if not quiet:
                        pass  # silently skip – verbose flag controls this
                    continue

                parsed_lines += 1
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                if prev_ts is not None and ts > prev_ts:
                    delta = (ts - prev_ts).total_seconds()
                    if delta >= threshold_seconds:
                        label, _ = classify_gap(delta)
                        gaps.append({
                            "gap_start":      prev_ts.isoformat(),
                            "gap_end":        ts.isoformat(),
                            "duration_sec":   round(delta, 2),
                            "duration_human": _human_duration(delta),
                            "severity":       label.strip(),
                            "start_line":     prev_line_no,
                            "end_line":       line_no,
                        })

                prev_ts = ts
                prev_line_no = line_no

    except FileNotFoundError:
        print(f"{C.RED}Error:{C.RESET} File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"{C.RED}Error:{C.RESET} Permission denied: {filepath}", file=sys.stderr)
        sys.exit(1)

    log_span = (last_ts - first_ts) if first_ts and last_ts else None

    return {
        "gaps":          gaps,
        "total_lines":   total_lines,
        "parsed_lines":  parsed_lines,
        "skipped_lines": skipped_lines,
        "first_ts":      first_ts,
        "last_ts":       last_ts,
        "log_span":      log_span,
    }


def _human_duration(seconds: float) -> str:
    """Return a human-readable duration string."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600)
    m = rem // 60
    return f"{h}h {m}m"


# ── Risk score ────────────────────────────────────────────────────────────────
def _risk_score(gaps: list) -> int:
    """Return 0-100 composite risk score."""
    if not gaps:
        return 0
    severities = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 2}
    raw = sum(severities.get(g["severity"], 0) for g in gaps)
    return min(raw, 100)


# ── Terminal reporter ─────────────────────────────────────────────────────────
def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET


def report_terminal(result: dict, filepath: str, threshold: float):
    gaps      = result["gaps"]
    risk      = _risk_score(gaps)
    risk_col  = C.RED if risk >= 60 else (C.YELLOW if risk >= 30 else C.GREEN)
    span_str  = _human_duration(result["log_span"].total_seconds()) \
                if result["log_span"] else "unknown"

    print()
    print(f"{C.BOLD}{'─'*62}{C.RESET}")
    print(f"{C.BOLD}  EVIDENCE PROTECTOR  –  Log Integrity Report{C.RESET}")
    print(f"{'─'*62}")
    print(f"  File      : {C.CYAN}{filepath}{C.RESET}")
    print(f"  Threshold : {threshold}s  ({_human_duration(threshold)})")
    print(f"  Log span  : {span_str}")
    if result["first_ts"]:
        print(f"  From      : {result['first_ts'].isoformat()}")
        print(f"  To        : {result['last_ts'].isoformat()}")
    print()
    print(f"  Lines     : {result['total_lines']:,} total  |  "
          f"{result['parsed_lines']:,} parsed  |  "
          f"{C.GREY}{result['skipped_lines']:,} skipped{C.RESET}")
    print(f"  Gaps found: {C.BOLD}{len(gaps)}{C.RESET}")
    print()

    # Risk bar
    print(f"  Risk score: {risk_col}{C.BOLD}{risk:>3}/100{C.RESET}  "
          f"{risk_col}{_bar(risk, 100)}{C.RESET}")
    print(f"{'─'*62}")

    if not gaps:
        print(f"\n  {C.GREEN}No suspicious gaps detected. Log appears intact.{C.RESET}\n")
        return

    # Severity counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for g in gaps:
        counts[g["severity"]] = counts.get(g["severity"], 0) + 1

    print(f"\n  Severity breakdown:")
    for sev, col in [("CRITICAL", C.RED), ("HIGH", C.YELLOW),
                     ("MEDIUM", C.CYAN), ("LOW", C.GREEN)]:
        n = counts[sev]
        if n:
            bar = col + _bar(n, len(gaps), width=20) + C.RESET
            print(f"    {col}{sev:<8}{C.RESET}  {n:>3}  {bar}")

    print(f"\n{'─'*62}")
    print(f"  {'#':<4} {'SEVERITY':<10} {'DURATION':<12} {'GAP START':<22} {'LINE':>5}")
    print(f"  {'─'*4} {'─'*10} {'─'*12} {'─'*22} {'─'*5}")

    for i, g in enumerate(gaps, start=1):
        _, col = classify_gap(g["duration_sec"])
        sev_display = col + g["severity"] + C.RESET
        print(f"  {i:<4} {sev_display:<20} "
              f"{g['duration_human']:<12} "
              f"{g['gap_start'][:19]:<22} "
              f"{g['start_line']:>5}")

    # Top gap callout
    worst = max(gaps, key=lambda g: g["duration_sec"])
    _, wcol = classify_gap(worst["duration_sec"])
    print(f"\n{'─'*62}")
    print(f"  {C.BOLD}Largest gap:{C.RESET}")
    print(f"    Start  : {worst['gap_start']}")
    print(f"    End    : {worst['gap_end']}")
    print(f"    Missing: {wcol}{C.BOLD}{worst['duration_human']}{C.RESET}  "
          f"(lines {worst['start_line']}–{worst['end_line']})")
    print(f"\n{'─'*62}\n")


# ── CSV export ────────────────────────────────────────────────────────────────
def report_csv(result: dict, output_path: str):
    fields = ["gap_start", "gap_end", "duration_sec", "duration_human",
              "severity", "start_line", "end_line"]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(result["gaps"])
    print(f"CSV saved → {output_path}  ({len(result['gaps'])} gap(s))")


# ── JSON export ───────────────────────────────────────────────────────────────
def report_json(result: dict, filepath: str, threshold: float, output_path: str):
    payload = {
        "meta": {
            "tool":            "Evidence Protector v1.0",
            "target_file":    filepath,
            "threshold_sec":  threshold,
            "total_lines":    result["total_lines"],
            "parsed_lines":   result["parsed_lines"],
            "skipped_lines":  result["skipped_lines"],
            "log_start":      result["first_ts"].isoformat() if result["first_ts"] else None,
            "log_end":        result["last_ts"].isoformat()  if result["last_ts"]  else None,
            "log_span_sec":   round(result["log_span"].total_seconds(), 2)
                              if result["log_span"] else None,
            "risk_score":     _risk_score(result["gaps"]),
        },
        "gaps": result["gaps"],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"JSON saved → {output_path}  ({len(result['gaps'])} gap(s))")


# ── Sample log generator (for demo / testing) ─────────────────────────────────
def generate_sample_log(path: str):
    """Write a synthetic log with injected gaps to demonstrate the tool."""
    from datetime import timedelta
    base = datetime(2024, 3, 10, 8, 0, 0)
    lines = []
    events = [
        (0,      "INFO",  "System boot complete"),
        (30,     "INFO",  "Auth service started"),
        (90,     "INFO",  "Database connected – pool size 10"),
        (150,    "INFO",  "User admin logged in from 10.0.0.1"),
        (210,    "INFO",  "Cron job: backup started"),
        # Normal gap ~1 min – continues
        (270,    "INFO",  "Backup complete"),
        # ── ATTACKER DELETES LOGS HERE ── 45-min gap follows
        (2970,   "WARN",  "Unexpected config change detected"),   # +45 min
        (3010,   "ERROR", "Failed login attempt: root@external"),
        (3045,   "INFO",  "Firewall rule modified"),
        (3080,   "WARN",  "Large data transfer to 203.0.113.5"),
        # Small 2-min gap
        (3200,   "INFO",  "User admin logged out"),
        # ── ANOTHER 2-HOUR GAP ──
        (10400,  "INFO",  "Scheduled maintenance window"),
        (10460,  "INFO",  "Service restarted"),
        (10520,  "ERROR", "Database replication lag detected"),
        (10580,  "INFO",  "Replication recovered"),
        (10640,  "INFO",  "All systems nominal"),
    ]
    for offset_sec, level, msg in events:
        ts = base + timedelta(seconds=offset_sec)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S")
        lines.append(f"{ts_str}  [{level:<5}]  {msg}")

    # Sprinkle some unparseable lines
    lines.insert(3,  "DEBUG kernel: process 1234 scheduled")
    lines.insert(8,  "--- marker ---")
    lines.insert(12, "continuation of previous error message")

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Sample log written → {path}  ({len(lines)} lines)")


# ── Argument parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evidence_protector",
        description="Scan log files for suspicious time gaps that may indicate tampering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evidence_protector.py system.log
  python evidence_protector.py system.log --threshold 120 --format json --out gaps.json
  python evidence_protector.py system.log --format csv --out report.csv
  python evidence_protector.py --generate-sample demo.log
        """,
    )
    p.add_argument("logfile", nargs="?", help="Path to the log file to scan")
    p.add_argument(
        "--threshold", "-t", type=float, default=300.0,
        metavar="SECONDS",
        help="Minimum gap duration to flag as suspicious (default: 300s = 5 min)",
    )
    p.add_argument(
        "--format", "-f", choices=["terminal", "csv", "json"], default="terminal",
        help="Output format (default: terminal)",
    )
    p.add_argument(
        "--out", "-o", metavar="FILE",
        help="Output file path (required for csv/json formats)",
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output during scanning",
    )
    p.add_argument(
        "--generate-sample", metavar="FILE",
        help="Generate a synthetic tampered log file for testing",
    )
    return p


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args = parser.parse_args()

    # Sample generator shortcut
    if args.generate_sample:
        generate_sample_log(args.generate_sample)
        print(f"\nNow run:  python evidence_protector.py {args.generate_sample} --threshold 60")
        return

    if not args.logfile:
        parser.print_help()
        sys.exit(0)

    if args.format in ("csv", "json") and not args.out:
        parser.error(f"--out FILE is required when using --format {args.format}")

    if not os.path.isfile(args.logfile):
        print(f"Error: '{args.logfile}' is not a file.", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"Scanning {args.logfile!r}  (threshold: {args.threshold}s) …", end=" ", flush=True)

    result = scan_log(args.logfile, args.threshold, quiet=args.quiet)

    if not args.quiet:
        print("done.")

    if args.format == "terminal":
        report_terminal(result, args.logfile, args.threshold)
    elif args.format == "csv":
        report_csv(result, args.out)
    elif args.format == "json":
        report_json(result, args.logfile, args.threshold, args.out)


if __name__ == "__main__":
    main()
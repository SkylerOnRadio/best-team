#!/usr/bin/env python3
"""
Evidence Protector v5.0 – Advanced Forensic Inference Engine
Now featuring organized hierarchical storage for forensic artifacts.
"""

from pathlib import Path
import argparse
import csv
import json
import os
import re
import sys
import platform
import time
import socket
import math
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

# ... [Keep C class and global patterns/constants the same as your original script] ...

# ── Updated Reporting Functions with Path Logic ─────────────────────────────

def get_next_filename(folder: Path, prefix: str, extension: str) -> Path:
    """Finds the next available n+1 filename in a specific folder."""
    i = 1
    while (folder / f"{prefix}{i}.{extension}").exists():
        i += 1
    return folder / f"{prefix}{i}.{extension}"

def report_csv_integrity(result: dict, report_dir: Path):
    csv_folder = report_dir / "csv"
    csv_folder.mkdir(parents=True, exist_ok=True)
    
    out_file = get_next_filename(csv_folder, "integrity_report", "csv")
    
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "gap_start", "gap_end", "duration_sec", "duration_human", "severity", "start_line", "end_line"])
        writer.writeheader()
        writer.writerows(result["gaps"])
    return out_file

def report_csv_behavioral(result: dict, report_dir: Path):
    csv_folder = report_dir / "csv"
    csv_folder.mkdir(parents=True, exist_ok=True)
    
    out_file = get_next_filename(csv_folder, "threat_actors", "csv")
    
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "hits", "failed_attempts", "span_human", "risk_tags"])
        writer.writeheader()
        for t in result["threats"]:
            row = {"ip": t["ip"], "hits": t["hits"], "failed_attempts": t["failed_attempts"], "span_human": t["span_human"], "risk_tags": ", ".join(t["risk_tags"])}
            writer.writerow(row)
    return out_file

def report_json(result: dict, report_dir: Path):
    json_folder = report_dir / "json"
    json_folder.mkdir(parents=True, exist_ok=True)
    
    out_file = get_next_filename(json_folder, "forensic_data", "json")
    
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2, default=str)
    return out_file

def report_html(result: dict, filepath: str, report_dir: Path):
    html_folder = report_dir / "html"
    html_folder.mkdir(parents=True, exist_ok=True)
    
    out_file = get_next_filename(html_folder, "visual_report", "html")
    
    # ... [Insert your existing HTML generation logic here] ...
    # Ensure you use 'out_file' in the 'with open' block below
    
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html) # 'html' variable from your original string formatting
    return out_file

# ── Updated Main Execution ───────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["all", "terminal", "json", "csv", "html"], default="all")
    args = p.parse_args()

    # 1. Resolve absolute paths for the input log
    log_path = Path(args.logfile).resolve()
    if not log_path.is_file():
        print(f"{C.RED}❌ Error: Log file not found at {log_path}{C.RESET}")
        sys.exit(1)

    # 2. Detect the user's Documents folder across all platforms
    # This correctly finds /home/user, /Users/user, or C:\Users\user
    report_root = Path.home() / "Documents" / "Forensic_Reports"
    
    try:
        report_root.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Emergency fallback if Documents is read-only/missing
        report_root = Path.cwd() / "reports"
        report_root.mkdir(parents=True, exist_ok=True)

    # 3. Analyze the log
    res = scan_log(str(log_path), args.threshold)
    
    # 4. Generate and Print Clickable Reports
    if args.format in ("all", "terminal"):
        report_terminal(res, str(log_path))

    # Note: .as_posix() converts \ to / so links are clickable on Windows
    if args.format in ("all", "csv"):
        f1 = report_csv_integrity(res, report_root)
        f2 = report_csv_behavioral(res, report_root) # Ensure this fn takes 2 args!
        print(f"📁 CSV Evidence:   file://{f1.resolve().as_posix()}")
        print(f"📁 CSV Behavioral: file://{f2.resolve().as_posix()}")

    if args.format in ("all", "html"):
        f_html = report_html(res, str(log_path), report_root)
        print(f"🌐 Visual Report: file://{f_html.resolve().as_posix()}")
    
    if args.format in ("all", "json"):
        f_json = report_json(res, report_root)
        print(f"📄 Raw JSON Data:  file://{f_json.resolve().as_posix()}")

if __name__ == "__main__":
    main()
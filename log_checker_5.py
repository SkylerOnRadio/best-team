#!/usr/bin/env python3
"""
Evidence Protector v5.0 – Advanced Forensic Inference Engine
Damage-Matrix Assessment with Shannon Entropy Detection and Probabilistic Risk Scoring.
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
import math
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

# ── Extraction Patterns ──────────────────────────────────────────────────────
TIMESTAMP_PATTERNS = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"], "ISO-8601"),
    (r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]", ["[%d/%b/%Y:%H:%M:%S %z]"], "Web (Apache/Nginx)"),
    (r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
     ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"], "Linux Syslog"),
    (r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", ["%Y/%m/%d %H:%M:%S"], "Windows Event"),
    (r"\d{2}:\d{2}:\d{2}\.\d+ \w{3} \w{3} \d{2} \d{4}", ["%H:%M:%S.%f %Z %a %b %d %Y"], "Network (Cisco)"),
    (r"\b1[0-9]{9}\b", None, "Unix Epoch"),
    (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", ["%m/%d/%Y %H:%M:%S"], "Generic (MM/DD/YYYY)"),
]

IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

ATTACK_KEYWORDS = {
    "FAILED_LOGIN": [r"failed", r"invalid user", r"auth fail", r"password", r"denied", r"incorrect"],
    "PRIV_ESCALATION": [r"sudo", r"su -", r"privilege", r"elevated", r"root", r"uid=0", r"chmod 777"],
    "SCANNING":    [r"nmap", r"scan", r"probe", r"port", r"sqli", r"xss"],
    "LOG_TAMPERING": [r"rm .*log", r"truncate", r"shred", r"history -c", r"clear-log", r"killall -9 syslogd"],
    "SENSITIVE_ACCESS": [r"/etc/shadow", r"/etc/passwd", r"\.ssh/", r"id_rsa", r"config\.php", r"\.env"],
    "SERVICE_EVENTS": [r"restarted", r"shutdown", r"panic", r"segfault", r"crashed", r"starting service", r"oom-killer"],
    "FILE_CHANGES": [r"new file", r"created", r"backdoor", r"shell\.sh", r"wget ", r"curl ", r"chmod \+x"],
    "UNUSUAL":     [r"proxy", r"tor", r"vpn", r"tunnel", r"hidden", r"suspicious"]
}

OFF_HOURS_START = 22 # 10 PM
OFF_HOURS_END = 6    # 6 AM
BRUTE_FORCE_THRESHOLD = 5
SPIKE_THRESHOLD_EPS = 50 

CURRENT_YEAR = datetime.now().year

# ── Core Intelligence Functions ─────────────────────────────────────────────

def calculate_entropy(data: str) -> float:
    """Detects obfuscated payloads by measuring character randomness."""
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def _risk_score(gaps: list, threats: list) -> int:
    """Evaluates risk using Probabilistic Saturation logic."""
    if not gaps and not threats: return 0
    zone_probs = {"integrity": 0.0, "access": 0.0, "persistence": 0.0, "privacy": 0.0, "continuity": 0.0}
    if any(g['type'] == 'REVERSED' for g in gaps): zone_probs["integrity"] = 0.95
    elif any(g['severity'] == 'CRITICAL' for g in gaps): zone_probs["integrity"] = 0.80
    elif gaps: zone_probs["integrity"] = 0.30
    for t in threats:
        tags = t["risk_tags"]
        if "PRIV_ESCALATION" in tags: zone_probs["access"] = max(zone_probs["access"], 0.90)
        if "BRUTE_FORCE_TARGET" in tags: zone_probs["access"] = max(zone_probs["access"], 0.70)
        if "LOG_TAMPER_ATTEMPT" in tags: zone_probs["persistence"] = max(zone_probs["persistence"], 0.99)
        if "UNUSUAL_FILE_CHANGE" in tags: zone_probs["persistence"] = max(zone_probs["persistence"], 0.75)
        if "SENSITIVE_FILE_ACCESS" in tags: zone_probs["privacy"] = max(zone_probs["privacy"], 0.85)
        if "SERVICE_INSTABILITY" in tags: zone_probs["continuity"] = max(zone_probs["continuity"], 0.60)
    combined_safe_prob = 1.0
    weights = {"integrity": 1.2, "access": 1.2, "persistence": 1.0, "privacy": 0.8, "continuity": 0.5}
    for zone, p in zone_probs.items():
        adjusted_p = min(p * weights[zone], 0.99)
        combined_safe_prob *= (1.0 - adjusted_p)
    return int(min((1.0 - combined_safe_prob) * 100, 100))

# ── Helper Utilities ─────────────────────────────────────────────────────────

def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

def _human_duration(seconds: float) -> str:
    seconds = abs(int(seconds))
    if seconds < 60: return f"{seconds}s"
    if seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600)
    return f"{h}h {rem // 60}m"

def get_system_metadata() -> Dict:
    return {
        "os": platform.system(),
        "ver": platform.release(),
        "arch": platform.machine(),
        "host": socket.gethostname(),
        "cpu": platform.processor(),
        "ts": datetime.now().isoformat()
    }

def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    for pattern, fmts, label in TIMESTAMP_PATTERNS:
        m = re.search(pattern, line)
        if not m: continue
        raw = m.group()
        if fmts is None:
            try: return datetime.fromtimestamp(int(raw), tz=None), label
            except: continue
        clean = re.sub(r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$", "", raw.strip("[]")).strip()
        for fmt in fmts:
            try:
                if "%Y" not in fmt and "%y" not in fmt:
                    dt = datetime.strptime(f"{CURRENT_YEAR} {clean}", f"%Y {fmt}")
                else: dt = datetime.strptime(clean, fmt)
                return dt, label
            except ValueError: continue
    return None, None

def detect_activity(line: str) -> List[str]:
    tags = []
    lower_line = line.lower()
    for category, patterns in ATTACK_KEYWORDS.items():
        if any(re.search(p, lower_line) for p in patterns): tags.append(category)
    return tags

# ── Core Analysis Engine ─────────────────────────────────────────────────────

def scan_log(filepath: str, threshold_seconds: float):
    start_time = time.time()
    gaps, total_lines, parsed_lines, skipped_lines = [], 0, 0, 0
    prev_ts, prev_line_no, first_ts, last_ts = None, 0, None, None
    log_type_counts = {}
    ip_stats = {} 
    obfuscated_payloads = 0

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
                        gaps.append({"type": "REVERSED" if delta < 0 else "GAP", "gap_start": prev_ts.isoformat(), "gap_end": ts.isoformat(), "duration_sec": round(delta, 2), "duration_human": _human_duration(delta), "severity": "REVERSED" if delta < 0 else ("CRITICAL" if delta > 3600 else "HIGH"), "start_line": prev_line_no, "end_line": line_no})
                ip_match = re.search(IP_PATTERN, line_content)
                if ip_match:
                    ip = ip_match.group()
                    tags = detect_activity(line_content)
                    if calculate_entropy(line_content) > 5.0:
                        tags.append("OBFUSCATED_PAYLOAD")
                        obfuscated_payloads += 1
                    if ip not in ip_stats: ip_stats[ip] = {"first_seen": ts, "last_seen": ts, "hits": 0, "failed_count": 0, "tags": set()}
                    data = ip_stats[ip]
                    data["last_seen"] = ts
                    data["hits"] += 1
                    if "FAILED_LOGIN" in tags: data["failed_count"] += 1
                    if ts.hour >= OFF_HOURS_START or ts.hour < OFF_HOURS_END: data["tags"].add("SUSPICIOUS_TIMING")
                    for t in tags: data["tags"].add(t)
                prev_ts, prev_line_no = ts, line_no
    except Exception: sys.exit(1)

    threats = []
    for ip, data in ip_stats.items():
        if data["failed_count"] >= BRUTE_FORCE_THRESHOLD: data["tags"].add("BRUTE_FORCE_TARGET")
        span = (data["last_seen"] - data["first_seen"]).total_seconds()
        if len(data["tags"]) > 0 or data["hits"] > 100:
            threats.append({"ip": ip, "risk_tags": sorted(list(data["tags"])), "hits": data["hits"], "failed_attempts": data["failed_count"], "span_human": _human_duration(span), "last_active": data["last_seen"].isoformat()})

    proc_time = time.time() - start_time
    return {
        "gaps": gaps, "threats": threats, "system_info": get_system_metadata(),
        "performance": {"time": round(proc_time, 4), "lps": round(total_lines/proc_time, 2) if proc_time > 0 else 0},
        "stats": {"log_type": max(log_type_counts, key=log_type_counts.get) if log_type_counts else "Unknown", "total_lines": total_lines, "parsed_lines": parsed_lines, "skipped_lines": skipped_lines, "log_span_sec": (last_ts - first_ts).total_seconds() if first_ts else 0, "obfuscation_count": obfuscated_payloads}
    }

# ── Enhanced Reporting Functions ──────────────────────────────────────────────

def report_terminal(result: dict, filepath: str):
    risk = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 75 else (C.YELLOW if risk >= 40 else C.GREEN)
    perf = result['performance']
    stats = result['stats']
    sys_info = result['system_info']

    print(f"\n{C.BOLD}{'━'*75}{C.RESET}")
    print(f" {C.CYAN}🛡️  EVIDENCE PROTECTOR v5.0{C.RESET} | {C.BOLD}Forensic Inference Engine{C.RESET}")
    print(f"{C.BOLD}{'━'*75}{C.RESET}")
    
    # Grid: System & Performance
    print(f" {C.BOLD}[SYSTEM CONTEXT]{C.RESET} {' ':<15} {C.BOLD}[PERFORMANCE]{C.RESET}")
    print(f"  Host: {sys_info['host']:<22}  Time: {perf['time']}s")
    print(f"  OS:   {sys_info['os']:<22}  Rate: {perf['lps']:,} lines/sec")
    print(f"  Type: {stats['log_type']:<22}  Span: {_human_duration(stats['log_span_sec'])}")
    
    # Risk Assessment
    print(f"\n {C.BOLD}[RISK ASSESSMENT]{C.RESET}")
    print(f"  Probability of Compromise: {risk_col}{C.BOLD}{risk:>3}%{C.RESET}  {risk_col}{_bar(risk, 100, width=40)}{C.RESET}")
    
    # Findings Summary
    print(f"\n {C.BOLD}[FORENSIC FINDINGS]{C.RESET}")
    gap_col = C.RED if result['gaps'] else C.GREEN
    threat_col = C.RED if len(result['threats']) > 3 else (C.YELLOW if result['threats'] else C.GREEN)
    
    print(f"  Timeline Integrity : {gap_col}{len(result['gaps']):>3} anomalies detected{C.RESET}")
    print(f"  Threat Entities    : {threat_col}{len(result['threats']):>3} active actors{C.RESET}")
    print(f"  Obfuscation Markers: {C.YELLOW}{stats['obfuscation_count']:>3} suspicious payloads{C.RESET}")

    # Top Threat Actors Table
    if result['threats']:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        print(f"  {'ENTITY (IP)':<16} | {'HITS':<6} | {'RISK INDICATORS'}")
        print(f"  {'-'*16}-+-{'-'*6}-+-{'-'*45}")
        for t in sorted(result['threats'], key=lambda x: x['hits'], reverse=True)[:5]:
            tags = ", ".join(t['risk_tags'][:3])
            print(f"  {C.YELLOW}{t['ip']:<16}{C.RESET} | {t['hits']:<6} | {C.GREY}{tags}{C.RESET}")

    print(f"\n{C.BOLD}{'━'*75}{C.RESET}")
    print(f" {C.DIM}Artifacts: report.json, reportN.html, reportN.csv, threatsN.csv{C.RESET}")
    print(f"{C.BOLD}{'━'*75}{C.RESET}\n")

def report_csv_integrity(result: dict):
    i = 1
    while os.path.exists(f"report{i}.csv"): i += 1
    with open(f"report{i}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "gap_start", "gap_end", "duration_sec", "duration_human", "severity", "start_line", "end_line"])
        writer.writeheader(); writer.writerows(result["gaps"])

def report_csv_behavioral(result: dict):
    i = 1
    while os.path.exists(f"threats{i}.csv"): i += 1
    with open(f"threats{i}.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "hits", "failed_attempts", "span_human", "risk_tags"])
        writer.writeheader()
        for t in result["threats"]:
            row = {"ip": t["ip"], "hits": t["hits"], "failed_attempts": t["failed_attempts"], "span_human": t["span_human"], "risk_tags": ", ".join(t["risk_tags"])}
            writer.writerow(row)

def report_json(result: dict):
    with open("report.json", "w") as f: json.dump(result, f, indent=2, default=str)

def report_html(result: dict, filepath: str):
    i = 1
    while os.path.exists(f"report{i}.html"): i += 1
    out_file = f"report{i}.html"
    risk = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 40 else "#10b981")
    sys = result['system_info']
    perf = result['performance']
    stats = result['stats']
    
    def gen_rows(subset):
        if not subset: return '<tr><td colspan="6" class="no-data">No threats detected in this zone.</td></tr>'
        return "".join([f"<tr><td><strong>{t['ip']}</strong></td><td>{t['hits']}</td><td>{t['failed_attempts']}</td><td>{t['span_human']}</td><td>{' '.join([f'<span class="tag tag-blue">{tag}</span>' for tag in t['risk_tags']])}</td></tr>" for t in subset])

    priv_esc = [t for t in result['threats'] if "PRIV_ESCALATION" in t['risk_tags']]
    brute_force = [t for t in result['threats'] if "BRUTE_FORCE_TARGET" in t['risk_tags']]
    integrity_threats = [t for t in result['threats'] if "LOG_TAMPER_ATTEMPT" in t['risk_tags']]

    html = f"""
    <!DOCTYPE html>
    <html lang="en"><head><meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    :root {{ --primary: #111827; --secondary: #4b5563; --danger: #ef4444; --warning: #f59e0b; --success: #10b981; --bg: #f3f4f6; --card-bg: #ffffff; }}
    body {{ font-family: 'Inter', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--primary); padding: 20px; line-height: 1.5; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    .card {{ background: var(--card-bg); border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; border: 1px solid #e5e7eb; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 24px; }}
    .risk-meter {{ height: 44px; background: #e5e7eb; border-radius: 22px; overflow: hidden; margin: 15px 0; position: relative; border: 1px solid #d1d5db; }}
    .risk-fill {{ height: 100%; background: {risk_color}; width: {risk}% }}
    .risk-text {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #fff; font-weight: 900; font-size: 18px; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }}
    
    details {{ border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px; background: #f9fafb; overflow: hidden; }}
    summary {{ padding: 16px; font-weight: 700; cursor: pointer; display: flex; align-items: center; border-left: 4px solid var(--secondary); list-style: none; }}
    summary::-webkit-details-marker {{ display: none; }}
    summary:hover {{ background: #f3f4f6; }}
    summary::after {{ content: '▼'; margin-left: auto; transition: transform 0.2s; font-size: 12px; }}
    details[open] summary::after {{ transform: rotate(180deg); }}
    details[open] summary {{ border-left: 4px solid var(--primary); background: #fff; border-bottom: 1px solid #e5e7eb; }}
    
    .inner-details {{ border: none; background: transparent; margin: 10px 0; border-radius: 0; }}
    .inner-details summary {{ padding: 10px 16px; font-size: 14px; background: #f1f5f9; border-left: 3px solid var(--secondary); }}
    
    .table-container {{ padding: 15px; background: #fff; overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #f1f5f9; }}
    th {{ background: #f8fafc; color: var(--secondary); text-transform: uppercase; font-size: 11px; }}
    .tag {{ padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-right: 4px; display: inline-block; }}
    .tag-red {{ background: #fee2e2; color: #991b1b; }}
    .tag-blue {{ background: #dbeafe; color: #1e40af; }}
    .story-card {{ background: #1e293b; color: #e2e8f0; padding: 20px; border-radius: 12px; margin-bottom: 24px; border-left: 5px solid #38bdf8; }}
    .meta-item {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px dashed #e5e7eb; }}
    .meta-item:last-child {{ border: none; }}
    .meta-label {{ color: var(--secondary); font-size: 12px; }}
    .meta-val {{ font-weight: 600; font-size: 13px; }}
    </style><title>Forensic Evidence - {os.path.basename(filepath)}</title></head>
    <body><div class="container">
        <div class="card">
            <h1>🛡️ Evidence Protector v5.0</h1>
            <p style="color:var(--secondary); margin-top:-10px;">Forensic Audit: <strong>{os.path.basename(filepath)}</strong></p>
            <div class="risk-meter"><div class="risk-fill"></div><span class="risk-text">SYSTEM COMPROMISE PROBABILITY: {risk}%</span></div>
        </div>

        <div class="grid">
            <div class="card">
                <h3>💻 System Metadata</h3>
                <div class="meta-item"><span class="meta-label">Hostname</span><span class="meta-val">{sys['host']}</span></div>
                <div class="meta-item"><span class="meta-label">Operating System</span><span class="meta-val">{sys['os']} ({sys['ver']})</span></div>
                <div class="meta-item"><span class="meta-label">Architecture</span><span class="meta-val">{sys['arch']}</span></div>
                <div class="meta-item"><span class="meta-label">Processor</span><span class="meta-val">{sys['cpu']}</span></div>
            </div>
            <div class="card">
                <h3>📈 Processing Intelligence</h3>
                <div class="meta-item"><span class="meta-label">Detected Log Type</span><span class="meta-val">{stats['log_type']}</span></div>
                <div class="meta-item"><span class="meta-label">Throughput Rate</span><span class="meta-val">{perf['lps']:,} lines/sec</span></div>
                <div class="meta-item"><span class="meta-label">Time To Process</span><span class="meta-val">{perf['time']}s</span></div>
                <div class="meta-item"><span class="meta-label">Temporal Span</span><span class="meta-val">{_human_duration(stats['log_span_sec'])}</span></div>
            </div>
        </div>

        <div class="story-card">
            <h3>📖 Forensic Reconstruction</h3>
            <p>Analysis of <strong>{stats['total_lines']:,}</strong> lines revealed <strong>{len(result['threats'])}</strong> actors. 
            Integrity confidence is <strong>{'LOW' if result['gaps'] else 'HIGH'}</strong>. 
            The most significant finding is <strong>{max([t['hits'] for t in result['threats']] + [0])}</strong> logged events from a single source IP.</p>
        </div>

        <div class="card">
            <h2 style="margin-top:0;">📂 Categorized Forensic Evidence</h2>
            
            <details>
                <summary>Zone 1: Timeline & Integrity</summary>
                <div class="table-container">
                    <details class="inner-details">
                        <summary>Timeline Gaps (Potential Deletion)</summary>
                        <table><thead><tr><th>Type</th><th>Duration</th><th>Lines</th></tr></thead>
                        <tbody>{"".join([f"<tr><td><span class='tag tag-red'>{g['severity']}</span></td><td>{g['duration_human']}</td><td>{g['start_line']}-{g['end_line']}</td></tr>" for g in result['gaps'] if g['type'] == 'GAP']) if result['gaps'] else '<tr><td colspan="3">No gaps detected.</td></tr>'}</tbody></table>
                    </details>
                    <details class="inner-details">
                        <summary>Anti-Forensic Commands</summary>
                        <table><tbody>{gen_rows(integrity_threats)}</tbody></table>
                    </details>
                </div>
            </details>

            <details>
                <summary>Zone 2: Access & Control</summary>
                <div class="table-container">
                    <details class="inner-details">
                        <summary>Brute Force Activity</summary>
                        <table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Span</th><th>Tags</th></tr></thead>
                        <tbody>{gen_rows(brute_force)}</tbody></table>
                    </details>
                    <details class="inner-details">
                        <summary>Privilege Escalation Attempts</summary>
                        <table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Span</th><th>Tags</th></tr></thead>
                        <tbody>{gen_rows(priv_esc)}</tbody></table>
                    </details>
                </div>
            </details>

            <details>
                <summary>Zone 3: Obfuscation & Data</summary>
                <div class="table-container">
                    <p style="font-size:12px; color:var(--secondary); padding:0 10px;">Lines with high Shannon Entropy (>5.0) indicate packed/encrypted payloads.</p>
                    <table><thead><tr><th>IP</th><th>Hits</th><th>Obfuscation Markers</th></tr></thead>
                    <tbody>{"".join([f"<tr><td>{t['ip']}</td><td>{t['hits']}</td><td><span class='tag tag-red'>ENTROPY_ALERT</span></td></tr>" for t in result['threats'] if "OBFUSCATED_PAYLOAD" in t['risk_tags']]) if any("OBFUSCATED_PAYLOAD" in t['risk_tags'] for t in result['threats']) else '<tr><td colspan="3">No obfuscated payloads detected.</td></tr>'}</tbody></table>
                </div>
            </details>
        </div>
        
        <footer style="text-align: center; color: var(--secondary); font-size: 11px;">Evidence Protector Engine v5.0 | {stats['parsed_lines']:,} parse success | {stats['skipped_lines']:,} noisy lines</footer>
    </div></body></html>
    """
    with open(out_file, "w", encoding="utf-8") as f: f.write(html)
    print(f"[*] Visual report generated → {out_file}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["all", "terminal", "json", "csv", "html"], default="all")
    args = p.parse_args()
    if not os.path.isfile(args.logfile): sys.exit(1)
    res = scan_log(args.logfile, args.threshold)
    if args.format in ("all", "terminal"): report_terminal(res, args.logfile)
    if args.format in ("all", "csv"): report_csv_integrity(res); report_csv_behavioral(res)
    if args.format in ("all", "html"): report_html(res, args.logfile)
    if args.format in ("all", "json"): report_json(res)

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Evidence Protector v2.8 – Damage-Matrix Forensic Engine
Evaluates system risk based on five impact zones: Integrity, Access, 
Persistence, Privacy, and Continuity.
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

# Behavioral & Forensic Attack Signatures
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
SPIKE_THRESHOLD_EPS = 50 # Events Per Second

CURRENT_YEAR = datetime.now().year

# ── Damage Matrix Evaluation ────────────────────────────────────────────────
def _risk_score(gaps: list, threats: list) -> int:
    """
    Evaluates risk using a Damage Matrix approach.
    Calculates impact scores for 5 zones and weights them.
    """
    if not gaps and not threats: return 0
    
    # Zone 1: Forensic Integrity (Timeline Tampering)
    integrity_damage = 0
    if any(g['type'] == 'REVERSED' for g in gaps): integrity_damage = 90
    elif any(g['severity'] == 'CRITICAL' for g in gaps): integrity_damage = 70
    elif any(g['severity'] == 'HIGH' for g in gaps): integrity_damage = 40
    elif gaps: integrity_damage = 20

    # Zone 2: System Control (Escalation & Takeover)
    control_damage = 0
    for t in threats:
        if "PRIV_ESCALATION" in t["risk_tags"]: control_damage = max(control_damage, 95)
        if "BRUTE_FORCE_TARGET" in t["risk_tags"]: control_damage = max(control_damage, 60)
        if "FAILED_LOGIN" in t["risk_tags"]: control_damage = max(control_damage, 20)

    # Zone 3: Persistence & Anti-Forensics (File Changes / Tampering)
    persistence_damage = 0
    for t in threats:
        if "LOG_TAMPER_ATTEMPT" in t["risk_tags"]: persistence_damage = max(persistence_damage, 100)
        if "UNUSUAL_FILE_CHANGE" in t["risk_tags"]: persistence_damage = max(persistence_damage, 80)
        if "SCANNING" in t["risk_tags"]: persistence_damage = max(persistence_damage, 30)

    # Zone 4: Data Privacy (Sensitive Information Access)
    privacy_damage = 0
    for t in threats:
        if "SENSITIVE_FILE_ACCESS" in t["risk_tags"]: privacy_damage = max(privacy_damage, 85)
        if "UNUSUAL" in t["risk_tags"]: privacy_damage = max(privacy_damage, 40)

    # Zone 5: Service Continuity (Crashes & Instability)
    continuity_damage = 0
    for t in threats:
        if "SERVICE_INSTABILITY" in t["risk_tags"]: continuity_damage = max(continuity_damage, 70)
        if "ACTIVITY_SPIKE" in t["risk_tags"]: continuity_damage = max(continuity_damage, 50)

    # Weighted Matrix Formula
    # We give high weight to System Control and Integrity as they indicate a direct compromise.
    weights = {
        "integrity": 0.25,
        "control": 0.30,
        "persistence": 0.20,
        "privacy": 0.15,
        "continuity": 0.10
    }

    final_damage = (
        (integrity_damage * weights["integrity"]) +
        (control_damage * weights["control"]) +
        (persistence_damage * weights["persistence"]) +
        (privacy_damage * weights["privacy"]) +
        (continuity_damage * weights["continuity"])
    )

    return int(min(final_damage, 100))

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

# ── Metadata Gathering ───────────────────────────────────────────────────────
def get_system_metadata() -> Dict:
    return {
        "os_type": platform.system(),
        "os_release": platform.release(),
        "hostname": socket.gethostname(),
        "scan_timestamp": datetime.now().isoformat()
    }

def get_file_metadata(filepath: str) -> Dict:
    try:
        stats = os.stat(filepath)
        return {
            "filename": os.path.basename(filepath),
            "size_bytes": stats.st_size,
            "modified_at": datetime.fromtimestamp(stats.st_mtime).isoformat()
        }
    except: return {}

# ── Parsing Helpers ──────────────────────────────────────────────────────────
def _strip_tz(raw: str) -> str:
    raw = raw.strip("[]")
    return re.sub(r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$", "", raw).strip()

def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    for pattern, fmts, label in TIMESTAMP_PATTERNS:
        m = re.search(pattern, line)
        if not m: continue
        raw = m.group()
        if fmts is None:
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
                        ip_stats[ip] = {
                            "first_seen": ts, "last_seen": ts, "hits": 0, "failed_count": 0, 
                            "off_hours_hits": 0, "tags": set()
                        }
                    
                    data = ip_stats[ip]
                    data["last_seen"] = ts
                    data["hits"] += 1
                    
                    if "FAILED_LOGIN" in tags: data["failed_count"] += 1
                    if "LOG_TAMPERING" in tags: data["tags"].add("LOG_TAMPER_ATTEMPT")
                    if "SENSITIVE_ACCESS" in tags: data["tags"].add("SENSITIVE_FILE_ACCESS")
                    if "SERVICE_EVENTS" in tags: data["tags"].add("SERVICE_INSTABILITY")
                    if "PRIV_ESCALATION" in tags: data["tags"].add("PRIV_ESCALATION")
                    if "FILE_CHANGES" in tags: data["tags"].add("UNUSUAL_FILE_CHANGE")
                    
                    if ts.hour >= OFF_HOURS_START or ts.hour < OFF_HOURS_END:
                        data["off_hours_hits"] += 1
                        data["tags"].add("SUSPICIOUS_TIMING")
                        
                    for t in tags: data["tags"].add(t)

                prev_ts, prev_line_no = ts, line_no
    except Exception as e:
        print(f"File Error: {e}", file=sys.stderr)
        sys.exit(1)

    threats = []
    for ip, data in ip_stats.items():
        if data["failed_count"] >= BRUTE_FORCE_THRESHOLD: data["tags"].add("BRUTE_FORCE_TARGET")
        span = (data["last_seen"] - data["first_seen"]).total_seconds()
        if span > 86400 * 2: data["tags"].add("PERSISTENT_ACTOR")
        if span > 0 and (data["hits"] / span) > SPIKE_THRESHOLD_EPS: data["tags"].add("ACTIVITY_SPIKE")

        if len(data["tags"]) > 0 or data["hits"] > 100:
            threats.append({
                "ip": ip,
                "risk_tags": sorted(list(data["tags"])),
                "hits": data["hits"],
                "failed_attempts": data["failed_count"],
                "off_hours_ratio": f"{(data['off_hours_hits']/data['hits']*100):.1f}%",
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
        "performance": {"processing_time_sec": round(processing_time, 4), "lines_per_sec": round(total_lines / processing_time, 2) if processing_time > 0 else 0},
        "stats": {"log_type": detected_log_type, "total_lines": total_lines, "parsed_lines": parsed_lines, "skipped_lines": skipped_lines, "log_span_sec": (last_ts - first_ts).total_seconds() if first_ts else 0, "first_ts": first_ts, "last_ts": last_ts}
    }

# ── Reporting Functions ──────────────────────────────────────────────────────
def report_terminal(result: dict, filepath: str, threshold: float):
    s, f, p = result["stats"], result["file_info"], result["performance"]
    risk = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 60 else (C.YELLOW if risk >= 30 else C.GREEN)
    
    print(f"\n{C.BOLD}{'─'*75}{C.RESET}")
    print(f"{C.BOLD}  🛡️  EVIDENCE PROTECTOR v2.8 – Damage-Matrix Assessment{C.RESET}")
    print(f"{'─'*75}")
    print(f"  Target File : {C.CYAN}{f.get('filename', filepath)}{C.RESET} ({s['log_type']})")
    print(f"  Risk Score  : {risk_col}{C.BOLD}{risk:>3}/100{C.RESET}  {risk_col}{_bar(risk, 100)}{C.RESET}")
    print(f"{'─'*75}")

    print(f"\n  {C.BOLD}[📊 IMPACT SUMMARY]{C.RESET}")
    print(f"    Timeline Anomalies : {C.YELLOW if result['gaps'] else C.GREEN}{len(result['gaps'])}{C.RESET}")
    print(f"    Threat Entities    : {C.RED if result['threats'] else C.GREEN}{len(result['threats'])}{C.RESET}")
    
    print(f"\n  {C.CYAN}Artifacts:{C.RESET} Visual matrix generated in reportN.html")
    print(f"{'─'*75}\n")

def report_csv_integrity(result: dict):
    i = 1
    while os.path.exists(f"report{i}.csv"): i += 1
    file_path = f"report{i}.csv"
    fields = ["type", "gap_start", "gap_end", "duration_sec", "duration_human", "severity", "start_line", "end_line"]
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields); writer.writeheader(); writer.writerows(result["gaps"])

def report_csv_behavioral(result: dict):
    i = 1
    while os.path.exists(f"threats{i}.csv"): i += 1
    file_path = f"threats{i}.csv"
    fields = ["ip", "hits", "failed_attempts", "off_hours_ratio", "span_human", "risk_tags"]
    with open(file_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields); writer.writeheader()
        for t in result["threats"]:
            row = t.copy(); row["risk_tags"] = ", ".join(row["risk_tags"])
            writer.writerow({k: row[k] for k in fields})

def report_json(result: dict, output_path: str = "report.json"):
    clean_result = result.copy()
    if clean_result["stats"]["first_ts"]: clean_result["stats"]["first_ts"] = clean_result["stats"]["first_ts"].isoformat()
    if clean_result["stats"]["last_ts"]: clean_result["stats"]["last_ts"] = clean_result["stats"]["last_ts"].isoformat()
    with open(output_path, "w") as fh: json.dump(clean_result, fh, indent=2)

def report_html(result: dict, filepath: str):
    i = 1
    while os.path.exists(f"report{i}.html"): i += 1
    out_file = f"report{i}.html"
    risk = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 60 else ("#f59e0b" if risk >= 30 else "#10b981")
    
    def gen_rows(subset):
        if not subset: return '<tr><td colspan="6" class="no-data">No threats detected in this zone.</td></tr>'
        return "".join([f"<tr><td><strong>{t['ip']}</strong></td><td>{t['hits']}</td><td>{t['failed_attempts']}</td><td>{t['off_hours_ratio']}</td><td>{t['span_human']}</td><td>{' '.join([f'<span class="tag tag-blue">{tag}</span>' for tag in t['risk_tags']])}</td></tr>" for t in subset])

    # Category filtering for Damage Matrix
    priv_esc = [t for t in result['threats'] if "PRIV_ESCALATION" in t['risk_tags']]
    brute_force = [t for t in result['threats'] if "BRUTE_FORCE_TARGET" in t['risk_tags']]
    integrity_threats = [t for t in result['threats'] if "LOG_TAMPER_ATTEMPT" in t['risk_tags']]
    data_threats = [t for t in result['threats'] if "SENSITIVE_FILE_ACCESS" in t['risk_tags']]
    spikes = [t for t in result['threats'] if "ACTIVITY_SPIKE" in t['risk_tags']]
    stability = [t for t in result['threats'] if "SERVICE_INSTABILITY" in t['risk_tags']]
    
    gap_data = [g for g in result['gaps'] if g['type'] == 'GAP']
    rev_data = [g for g in result['gaps'] if g['type'] == 'REVERSED']

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            :root {{ --primary: #111827; --secondary: #4b5563; --danger: #ef4444; --warning: #f59e0b; --success: #10b981; --bg: #f3f4f6; --card-bg: #ffffff; }}
            body {{ font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--primary); padding: 20px; line-height: 1.5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .card {{ background: var(--card-bg); border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 24px; margin-bottom: 24px; border: 1px solid #e5e7eb; }}
            .risk-meter {{ height: 36px; background: #e5e7eb; border-radius: 18px; overflow: hidden; margin: 15px 0; position: relative; border: 1px solid #d1d5db; }}
            .risk-fill {{ height: 100%; background: {risk_color}; width: {risk}% }}
            .risk-text {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #fff; font-weight: 900; text-shadow: 0 1px 2px rgba(0,0,0,0.5); font-size: 18px; }}
            
            details {{ border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 12px; background: #f9fafb; overflow: hidden; }}
            summary {{ padding: 16px; font-weight: 700; cursor: pointer; display: flex; align-items: center; user-select: none; border-left: 4px solid var(--secondary); }}
            summary:hover {{ background: #f3f4f6; }}
            summary::after {{ content: '▼'; margin-left: auto; transition: transform 0.2s; }}
            details[open] summary::after {{ transform: rotate(180deg); }}
            details[open] summary {{ border-left: 4px solid var(--primary); }}
            
            .table-container {{ padding: 15px; background: #fff; overflow-x: auto; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #f1f5f9; }}
            th {{ background: #f8fafc; color: var(--secondary); text-transform: uppercase; font-size: 11px; }}
            .tag {{ padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-right: 4px; display: inline-block; }}
            .tag-red {{ background: #fee2e2; color: #991b1b; }}
            .tag-blue {{ background: #dbeafe; color: #1e40af; }}
            .badge {{ background: var(--primary); color: white; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin-left: 10px; }}
            .no-data {{ text-align: center; color: var(--secondary); padding: 20px; font-style: italic; }}
        </style>
        <title>Forensic Damage Matrix - {os.path.basename(filepath)}</title>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🛡️ Log Integrity Checker V 4.2</h1>
                <p style="color:var(--secondary);">Damage Matrix Audit: <strong>{os.path.basename(filepath)}</strong></p>
                <div class="risk-meter"><div class="risk-fill"></div><span class="risk-text">OVERALL SYSTEM DAMAGE: {risk}%</span></div>
            </div>

            <div class="card" style="border-top: 5px solid #ef4444;">
                <h2 style="color:#ef4444;">🚨 Zone 1: Integrity & Anti-Forensics</h2>
                <details>
                    <summary>Timeline Gaps (Potential Deletion) <span class="badge">{len(gap_data)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>Severity</th><th>Duration</th><th>Window</th><th>Lines</th></tr></thead>
                    <tbody>{"".join([f"<tr><td><span class='tag tag-red'>{g['severity']}</span></td><td>{g['duration_human']}</td><td>{g['gap_start'][:19]} &rarr; {g['gap_end'][:19]}</td><td>{g['start_line']}-{g['end_line']}</td></tr>" for g in gap_data]) if gap_data else '<tr><td colspan="4" class="no-data">No gaps detected.</td></tr>'}</tbody></table></div>
                </details>
                <details>
                    <summary>Anti-Forensic Commands <span class="badge">{len(integrity_threats)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(integrity_threats)}</tbody></table></div>
                </details>
            </div>

            <div class="card" style="border-top: 5px solid #f59e0b;">
                <h2 style="color:#f59e0b;">🔐 Zone 2: System Control & Access</h2>
                <details>
                    <summary>Privilege Escalation Events <span class="badge">{len(priv_esc)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(priv_esc)}</tbody></table></div>
                </details>
                <details>
                    <summary>Brute Force Activity <span class="badge">{len(brute_force)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(brute_force)}</tbody></table></div>
                </details>
            </div>

            <div class="card" style="border-top: 5px solid #3b82f6;">
                <h2 style="color:#3b82f6;">📁 Zone 3: Data Privacy & Information</h2>
                <details>
                    <summary>Sensitive File Access Attempts <span class="badge">{len(data_threats)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(data_threats)}</tbody></table></div>
                </details>
            </div>

            <div class="card" style="border-top: 5px solid #10b981;">
                <h2 style="color:#10b981;">⚙️ Zone 4: Service Continuity</h2>
                <details>
                    <summary>Activity Spikes <span class="badge">{len(spikes)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(spikes)}</tbody></table></div>
                </details>
                <details>
                    <summary>Service Crashes & Events <span class="badge">{len(stability)}</span></summary>
                    <div class="table-container"><table><thead><tr><th>IP</th><th>Hits</th><th>Failures</th><th>Off-Hours</th><th>Span</th><th>Tags</th></tr></thead><tbody>{gen_rows(stability)}</tbody></table></div>
                </details>
            </div>
            
            <footer style="text-align: center; color: var(--secondary); font-size: 11px;">
                Evidence Protector Engine v2.8 | Managed Damage Assessment
            </footer>
        </div>
    </body>
    </html>
    """
    with open(out_file, "w", encoding="utf-8") as f: f.write(html)
    print(f"[*] Damage Matrix report generated → {out_file}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("logfile", help="Path to log file")
    p.add_argument("--threshold", "-t", type=float, default=300.0)
    p.add_argument("--format", choices=["all", "terminal", "json", "csv", "html"], default="all")
    p.add_argument("--out", "-o", help="Specific JSON path")
    args = p.parse_args()

    if not os.path.isfile(args.logfile): sys.exit(1)
    res = scan_log(args.logfile, args.threshold)
    
    if args.format in ("all", "terminal"): report_terminal(res, args.logfile, args.threshold)
    if args.format in ("all", "csv"):
        report_csv_integrity(res)
        report_csv_behavioral(res)
    if args.format in ("all", "html"): report_html(res, args.logfile)
    if args.format in ("all", "json"): report_json(res, args.out if args.out else "report.json")

if __name__ == "__main__":
    main()
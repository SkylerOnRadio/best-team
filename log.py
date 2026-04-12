#!/usr/bin/env python3
"""
Log Detector and Foreign Threat Analysis  v2.2 (Optimized + Full UI + Smoothed Risk)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
High-performance, streaming, multi-threaded forensic log analysis engine.
Preserved Terminal UI & Report Architecture with optimized internal parsing
and an asymptotic risk probability model.
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import argparse
import csv
import json
import math
import mmap
import multiprocessing
import os
import platform
import queue
import re
import socket
import sys
import threading
import time
import gzip
import bz2
import html as html_mod
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════════
# ── COLOUR / IDENTITY ─────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

class C:
    RESET   = "\033[0m"  if USE_COLOUR else ""
    BOLD    = "\033[1m"  if USE_COLOUR else ""
    RED     = "\033[91m" if USE_COLOUR else ""
    YELLOW  = "\033[93m" if USE_COLOUR else ""
    CYAN    = "\033[96m" if USE_COLOUR else ""
    GREEN   = "\033[92m" if USE_COLOUR else ""
    GREY    = "\033[90m" if USE_COLOUR else ""
    DIM     = "\033[2m"  if USE_COLOUR else ""
    MAGENTA = "\033[95m" if USE_COLOUR else ""

PROJECT_NAME    = "Log Detector and Foreign Threat Analysis"
PROJECT_VERSION = "2.2.1"
REPORT_ROOT_DIR = f"Forensic_Reports"

# ═══════════════════════════════════════════════════════════════════════════════
# ── GLOBAL PRE-COMPILED PATTERNS ──────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

# Optimized IPv4 + IPv6 Dual Stack Regex
IP_RE = re.compile(
    r'\b(?:'
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r'|'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}'
    r'|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|::(?:ffff(?::0{1,4})?:)?'
      r'(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}'
      r'(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}:'
      r'(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}'
      r'(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])'
    r')\b'
)

MONTH_MAP = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}

DATE_REGEX = re.compile(r'\b(\d{4})[-/](\d{2})[-/](\d{2})[T\s](\d{2}):(\d{2}):(\d{2})\b')

# Fallback Signatures
SIGS_FALLBACK = {
    "FAILED_LOGIN": r"failed|invalid user|auth fail|password|denied|incorrect|authentication failure|bad password|login failed",
    "PRIV_ESCALATION": r"sudo|su -|privilege|elevated|root|uid=0|chmod 777|visudo|pkexec|doas|newgrp",
    "SCANNING": r"nmap|scan|probe|port|sqli|xss|select.*from|union.*select|nikto|masscan|zmap|dirbuster|gobuster|ffuf|nuclei|(?:GET|POST|HEAD)\s+/\S*\?.*=",
    "LOG_TAMPERING": r"rm .*log|truncate|shred|history -c|clear-log|killall -9 syslogd|echo.*>.*\.log|> /var/log|unlink.*log|wipe|auditctl -e 0",
    "SENSITIVE_ACCESS": r"/etc/shadow|/etc/passwd|\.ssh/|id_rsa|config\.php|\.env|/proc/self|/root/\.|lsass|SAM database|\.htpasswd|wp-config\.php|database\.yml",
    "SERVICE_EVENTS": r"restarted|shutdown|panic|segfault|crashed|oom-killer|kernel: BUG|double free|use-after-free|stack smashing",
    "DATA_EXFIL": r"curl.*http|wget.*http|nc -e|/dev/tcp|base64.*decode|python.*socket|powershell.*download|certutil.*url",
    "LATERAL_MOVEMENT": r"ssh.*@|scp |rsync |psexec|wmic|net use \\\\|xfreerdp|rdesktop|winrm|evil-winrm|impacket"
}

KILL_CHAIN_STAGES = ("SCANNING", "FAILED_LOGIN", "PRIV_ESCALATION", "SENSITIVE_ACCESS", "LOG_TAMPERING")

# ── Tunable parameters ────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD      = 5
BRUTE_FORCE_WINDOW_MIN     = 10
DISTRIBUTED_ATTACK_WINDOW  = 300
DISTRIBUTED_FAIL_THRESHOLD = 15
SESSION_INACTIVITY_SEC     = 1800
ENTROPY_BASELINE_LINES     = 500
ENTROPY_STD_MULTIPLIER     = 2.0
ENTROPY_ABS_MIN            = 4.5
RARE_TEMPLATE_THRESHOLD    = 2
READ_BUFFER                = 1 << 23   # 8 MB
CHUNK_MIN_BYTES            = 1 << 22   # 4 MB
CPU_LIMIT_PCT              = 25
THROTTLE_WINDOW_S          = 0.05
THROTTLE_BATCH             = 50
CURRENT_YEAR               = datetime.now().year

# ═══════════════════════════════════════════════════════════════════════════════
# ── FAST UTILS ────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def load_sigs(config_path: Optional[str] = None) -> Tuple[Tuple[str, re.Pattern], ...]:
    """Loads patterns from external JSON or uses internal defaults."""
    data = SIGS_FALLBACK.copy()
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f: data.update(json.load(f))
        except: pass
    elif os.path.exists("signatures.json"):
        try:
            with open("signatures.json", 'r') as f: data.update(json.load(f))
        except: pass
    return tuple((tag, re.compile(pat, re.I)) for tag, pat in data.items())

def _iter_line_bytes(chunk_bytes: bytes) -> Generator[str, None, None]:
    """High-speed generator to avoid massive splitlines() memory usage."""
    start = 0
    while True:
        pos = chunk_bytes.find(b'\n', start)
        if pos == -1:
            if start < len(chunk_bytes):
                yield chunk_bytes[start:].decode('utf-8', 'replace')
            break
        yield chunk_bytes[start:pos].decode('utf-8', 'replace')
        start = pos + 1

def fast_parse_timestamp(line: str) -> Tuple[datetime, str]:
    """Optimized slicing: 10x faster than strptime for core formats.
    Includes regex fallback for embedded JSON or varied prefix formats.
    """
    if not line or len(line) < 15:
        return None, None
    try:
        # ── ISO-8601 & Nginx Error (2024-10-27 10:00:00 or 2024/10/27 10:00:00)
        if len(line) >= 19 and line[4] in ('-', '/') and line[7] in ('-', '/'):
            return datetime(int(line[0:4]), int(line[5:7]), int(line[8:10]),
                            int(line[11:13]), int(line[14:16]), int(line[17:19])), "ISO-8601/Nginx Error"
 
        # ── Linux Syslog  (Oct 27 10:00:00) ─────────────────────────────────
        month_abbr = line[0:3].capitalize()
        if month_abbr in MONTH_MAP and len(line) >= 15:
            day_str = line[4:6].strip()
            if day_str.isdigit():
                dt = datetime(CURRENT_YEAR, MONTH_MAP[month_abbr], int(day_str),
                              int(line[7:9]), int(line[10:12]), int(line[13:15]))
                if dt > datetime.now() + timedelta(days=1):
                    dt = dt.replace(year=CURRENT_YEAR - 1)
                return dt, "Linux Syslog"
 
        # ── Apache/Nginx  (... [27/Oct/2024:10:00:00 +0000] ...) ────────────
        bracket = line.find('[')
        if 0 <= bracket < 100:                       # Changed to allow bracket at index 0 and longer IP prefixes
            ts_part = line[bracket + 1:]
            if len(ts_part) >= 20 and ts_part[2] == '/' and ts_part[6] == '/':
                day_str = ts_part[0:2].strip()
                if day_str.isdigit():
                    mon = MONTH_MAP.get(ts_part[3:6].capitalize())
                    if mon:
                        year = int(ts_part[7:11])
                        hour = int(ts_part[12:14])
                        minu = int(ts_part[15:17])
                        sec  = int(ts_part[18:20])
                        return datetime(year, mon, int(day_str), hour, minu, sec), "Web (Apache/Nginx)"
            
            # ── Apache Error Log ([Sun Oct 27 10:00:00.123 2024]) ───────────
            if len(ts_part) >= 24 and ts_part[3] == ' ' and ts_part[7] == ' ':
                mon = MONTH_MAP.get(ts_part[4:7].capitalize())
                if mon:
                    day_str = ts_part[8:10].strip()
                    if day_str.isdigit():
                        hour = int(ts_part[11:13])
                        minu = int(ts_part[14:16])
                        sec = int(ts_part[17:19])
                        rb = ts_part.find(']')
                        if rb != -1:
                            year_str = ts_part[rb-4:rb]
                            if year_str.isdigit():
                                return datetime(int(year_str), mon, int(day_str), hour, minu, sec), "Apache Error"

        # ── Windows Event  (10/27/2024 10:00:00) ────────────────────────────
        if len(line) >= 19 and line[2] == '/' and line[5] == '/':
            return datetime(int(line[6:10]), int(line[0:2]), int(line[3:5]),
                            int(line[11:13]), int(line[14:16]), int(line[17:19])), "Windows Event"
 
    except (ValueError, IndexError):
        pass
        
    # ── Fallback Regex (For JSON fields, indented lines, etc.) ───────────────
    try:
        m = DATE_REGEX.search(line)
        if m:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6))), "ISO-8601 (Embedded)"
    except ValueError:
        pass

    return None, None

def _throttle_init(cpu_limit_pct: float) -> Dict:
    allowed_frac = max(0.05, min(cpu_limit_pct / 100.0, 0.95))
    return {
        "allowed": THROTTLE_WINDOW_S * allowed_frac,
        "sleep_budget": THROTTLE_WINDOW_S * (1.0 - allowed_frac),
        "window_start": time.monotonic(),
        "work_start": time.monotonic(),
        "work_used": 0.0,
    }

def _throttle_tick(state: Dict) -> None:
    now = time.monotonic()
    state["work_used"] += now - state["work_start"]
    state["work_start"] = now
    window_elapsed = now - state["window_start"]
    if state["work_used"] >= state["allowed"]:
        sleep_for = max(0.0, state["sleep_budget"] - (window_elapsed - state["work_used"]))
        if sleep_for > 0: time.sleep(sleep_for)
        state["window_start"] = time.monotonic(); state["work_start"] = time.monotonic(); state["work_used"] = 0.0
    elif window_elapsed >= THROTTLE_WINDOW_S:
        state["window_start"] = time.monotonic(); state["work_start"] = time.monotonic(); state["work_used"] = 0.0

def calculate_entropy(data: str) -> float:
    if not data or len(data) < 10: return 0.0
    length = len(data)
    counts = Counter(data)
    inv_len = 1.0 / length
    return -sum((c * inv_len) * math.log2(c * inv_len) for c in counts.values())

def compute_entropy_baseline(lines: List[str]) -> Tuple[float, float]:
    values = [v for l in lines if (v := calculate_entropy(l)) > 0]
    if not values: return 5.0, 0.5
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var)

def log_template(line: str) -> str:
    t = re.sub(r'\d+', '<N>', line)
    t = re.sub(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b', '<IPv6>', t)
    return re.sub(r'\s+', ' ', t).strip()[:120]

# ═══════════════════════════════════════════════════════════════════════════════
# ── WORKER (Process level) ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _worker(filepath: str, start: int, end: int, threshold_seconds: float, ioc_set_frozen: frozenset, 
            entropy_threshold: float, result_queue: multiprocessing.Queue, cpu_limit_pct: float, sigs: tuple) -> None:
    try: os.nice(15)
    except: pass
    
    throttle = _throttle_init(cpu_limit_pct)
    gaps, ip_stats, template_counts = [], {}, Counter()
    total_lines, parsed_lines, obfuscated_cnt, batch_ctr = 0, 0, 0, 0
    prev_ts, log_type = None, None
    time_buckets = defaultdict(list)

    try:
        with open(filepath, "rb") as raw_fh:
            try:
                mm = mmap.mmap(raw_fh.fileno(), 0, access=mmap.ACCESS_READ)
                mm.seek(start)
                chunk_bytes = mm.read(end - start)
                mm.close()
            except:
                raw_fh.seek(start); chunk_bytes = raw_fh.read(end - start)

        for line_content in _iter_line_bytes(chunk_bytes):
            total_lines += 1; batch_ctr += 1
            if batch_ctr >= THROTTLE_BATCH:
                _throttle_tick(throttle); batch_ctr = 0

            ts, ltype = fast_parse_timestamp(line_content)
            if not ts: continue
            parsed_lines += 1
            if not log_type: log_type = ltype

            if prev_ts:
                diff = (ts - prev_ts).total_seconds()
                if diff >= threshold_seconds:
                    gaps.append({"type": "GAP", "gap_start": prev_ts.isoformat(), "gap_end": ts.isoformat(), 
                                 "duration_human": str(ts-prev_ts), "duration_seconds": diff, 
                                 "severity": "CRITICAL" if diff > 3600 else "HIGH", "start_line": total_lines, "end_line": total_lines + 1})
                elif diff < -10:
                    gaps.append({"type": "REVERSED", "gap_start": prev_ts.isoformat(), "gap_end": ts.isoformat(), 
                                 "duration_human": str(ts-prev_ts), "duration_seconds": diff, 
                                 "severity": "CRITICAL", "start_line": total_lines, "end_line": total_lines + 1})

            ip_m = IP_RE.search(line_content)
            if ip_m:
                ip = ip_m.group()
                if ip not in ip_stats:
                    ip_stats[ip] = {"first": ts, "last": ts, "hits": 0, "fails": deque(maxlen=50), "events": [], "tags": set()}
                s = ip_stats[ip]; s["hits"] += 1; s["last"] = ts; s["events"].append(ts)
                
                is_fail = False
                for tag, sig in sigs:
                    if sig.search(line_content):
                        s["tags"].add(tag)
                        if tag == "FAILED_LOGIN": is_fail = True
                
                if ip in ioc_set_frozen: s["tags"].add("KNOWN_MALICIOUS_IOC")
                if calculate_entropy(line_content) > entropy_threshold:
                    s["tags"].add("HIGH_ENTROPY_PAYLOAD"); obfuscated_cnt += 1
                
                time_buckets[int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)].append((ip, is_fail))

            prev_ts = ts
            template_counts[log_template(line_content)] += 1
            
    except Exception as exc:
        result_queue.put({"error": str(exc)}); return

    result_queue.put({
        "gaps": gaps, "ip_stats": ip_stats, "template_counts": dict(template_counts),
        "obfuscated_count": obfuscated_cnt, "total_lines": total_lines, "parsed_lines": parsed_lines,
        "log_type": log_type, "time_buckets": dict(time_buckets)
    })

def _worker_compressed(filepath, threshold_seconds, ioc_set_frozen, entropy_threshold, result_queue, cpu_limit_pct, sigs) -> None:
    try: os.nice(15)
    except: pass
    throttle = _throttle_init(cpu_limit_pct)
    opener = gzip.open if filepath.endswith(".gz") else bz2.open
    gaps, ip_stats, template_counts = [], {}, Counter()
    total_lines, parsed_lines, obfuscated_cnt, batch_ctr = 0, 0, 0, 0
    prev_ts, log_type = None, None
    time_buckets = defaultdict(list)

    try:
        with opener(filepath, "rt", encoding="utf-8", errors="replace") as fh:
            for line_content in fh:
                total_lines += 1; batch_ctr += 1
                if batch_ctr >= THROTTLE_BATCH: _throttle_tick(throttle); batch_ctr = 0
                ts, ltype = fast_parse_timestamp(line_content)
                if not ts: continue
                parsed_lines += 1
                if not log_type: log_type = ltype
                if prev_ts:
                    diff = (ts - prev_ts).total_seconds()
                    if diff >= threshold_seconds or diff < -10:
                        gaps.append({"type": "GAP" if diff > 0 else "REVERSED", "gap_start": prev_ts.isoformat(), 
                                     "gap_end": ts.isoformat(), "duration_human": str(ts-prev_ts), "duration_seconds": diff, 
                                     "severity": "HIGH", "start_line": total_lines, "end_line": total_lines + 1})
                ip_m = IP_RE.search(line_content)
                if ip_m:
                    ip = ip_m.group()
                    if ip not in ip_stats: ip_stats[ip] = {"first": ts, "last": ts, "hits": 0, "fails": deque(maxlen=50), "events": [], "tags": set()}
                    s = ip_stats[ip]; s["hits"] += 1; s["last"] = ts; s["events"].append(ts)
                    is_fail = False
                    for tag, sig in sigs:
                        if sig.search(line_content):
                            s["tags"].add(tag)
                            if tag == "FAILED_LOGIN": is_fail = True
                    if ip in ioc_set_frozen: s["tags"].add("KNOWN_MALICIOUS_IOC")
                    if calculate_entropy(line_content) > entropy_threshold: s["tags"].add("HIGH_ENTROPY_PAYLOAD"); obfuscated_cnt += 1
                    time_buckets[int(ts.timestamp() // 300)].append((ip, is_fail))
                prev_ts = ts
                template_counts[log_template(line_content)] += 1
    except Exception as exc:
        result_queue.put({"error": str(exc)}); return
    result_queue.put({"gaps": gaps, "ip_stats": ip_stats, "template_counts": dict(template_counts), "obfuscated_count": obfuscated_cnt,
                      "total_lines": total_lines, "parsed_lines": parsed_lines, "log_type": log_type, "time_buckets": dict(time_buckets)})

# ═══════════════════════════════════════════════════════════════════════════════
# ── REFINED RISK SCORING (Asymptotic Smoothing) ───────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _risk_zones(gaps: list, threats: list) -> Dict[str, float]:
    if not gaps and not threats: 
        return {z: 0.0 for z in ("integrity","access","persistence","privacy","continuity","exfiltration","lateral")}
    
    tag_actors = defaultdict(list)
    for t in threats:
        for tag in t["risk_tags"]: 
            tag_actors[tag].append(t)
            
    def get_hits(tag: str) -> int:
        return sum(t["hits"] for t in tag_actors[tag])
        
    def get_actors(tag: str) -> int:
        return len(tag_actors[tag])

    def points(base_weight: float, tag: str) -> float:
        actors = get_actors(tag)
        if actors == 0: 
            return 0.0
        hits = get_hits(tag)
        # Base risk scales linearly with unique actors, and logarithmically with volume (hits)
        return (base_weight * actors) + (base_weight * 0.5 * math.log10(max(1, hits)))

    # Calculate raw risk points per zone based on severity
    rev_gaps = len([g for g in gaps if g["type"] == "REVERSED"])
    norm_gaps = len([g for g in gaps if g["type"] == "GAP"])
    integrity_pts = (rev_gaps * 0.8) + (norm_gaps * 0.2)

    access_pts = (points(0.4, "PRIV_ESCALATION") + 
                  points(0.05, "FAILED_LOGIN") + 
                  points(0.1, "BRUTE_FORCE_BURST") + 
                  points(0.2, "DISTRIBUTED_ATTACK"))

    zones = {
        "integrity": integrity_pts,
        "access": access_pts,
        "persistence": points(0.5, "LOG_TAMPERING"),
        "privacy": points(0.3, "SENSITIVE_ACCESS"),
        "continuity": points(0.2, "SERVICE_EVENTS"),
        "exfiltration": points(0.4, "DATA_EXFIL"),
        "lateral": points(0.3, "LATERAL_MOVEMENT")
    }
    
    # Asymptotic smoothing: 1 - exp(-x) gracefully maps [0, infinity] to a [0.0, 1.0) probability
    return {z: 1.0 - math.exp(-pts) for z, pts in zones.items()}

def _risk_score(gaps: list, threats: list) -> int:
    zone_probs = _risk_zones(gaps, threats)
    
    # Combine independent zone probabilities using P(A or B) = 1 - P(not A) * P(not B)
    safety = 1.0
    for p in zone_probs.values(): 
        safety *= (1.0 - p)
        
    # Contextual Modifiers (Kill-Chains and IOCs compress the remaining safety margin)
    kc_count = sum(1 for t in threats if "KILL_CHAIN_DETECTED" in t["risk_tags"])
    ioc_count = sum(1 for t in threats if t.get("is_ioc"))
    
    # Each confirmed Kill-Chain reduces safety by 30%, IOC by 15%
    safety *= (0.70 ** kc_count)
    safety *= (0.85 ** ioc_count)
    
    # Guard against minor floating point drift
    final_prob = max(0.0, 1.0 - safety)
    
    # Cap at 99%
    return min(int(final_prob * 100), 99)

def resolve_output_dir() -> Dict[str, str]:
    """
    Creates: ~/Documents/Reports - Log Detector/[csv|html|json]/DD-MM-YYYY/
    """
    date_str = datetime.now().strftime("%d-%m-%Y")
    documents = os.path.join(os.path.expanduser("~"), "Documents", REPORT_ROOT_DIR)
    
    dirs = {
        "csv":  os.path.join(documents, "csv", date_str),
        "html": os.path.join(documents, "html", date_str),
        "json": os.path.join(documents, "json", date_str),
    }
    
    # Create all necessary subdirectories
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
        
    return dirs

def make_output_paths(dirs: Dict[str, str]) -> Dict[str, str]:
    """
    Generates file paths dynamically checking the directory for the Nth scan.
    Format: x_filename_HH-MM-SS.ext
    """
    ts = datetime.now().strftime("%H-%M-%S")
    
    # Calculate 'x' by checking existing files in the 'csv' directory for today
    highest_n = 0
    for filename in os.listdir(dirs["csv"]):
        match = re.match(r"^(\d+)_", filename)
        if match:
            highest_n = max(highest_n, int(match.group(1)))
            
    n = highest_n + 1

    return {
        "csv_integrity":  os.path.join(dirs["csv"], f"{n}_integrity_{ts}.csv"),
        "csv_behavioral": os.path.join(dirs["csv"], f"{n}_behavioral_{ts}.csv"),
        "html":           os.path.join(dirs["html"], f"{n}_dashboard_{ts}.html"),
        "json":           os.path.join(dirs["json"], f"{n}_report_{ts}.json")
    }


def to_file_url(path: str) -> str:
    abs_path = os.path.abspath(path).replace("\\", "/")
    if not abs_path.startswith("/"):
        abs_path = "/" + abs_path
    return f"file://{abs_path}"

def session_reconstruct(events: List[datetime]) -> List[Dict]:
    if not events: return []
    sessions, s_start, s_last, count = [], events[0], events[0], 1
    for ts in events[1:]:
        if (ts - s_last).total_seconds() > SESSION_INACTIVITY_SEC:
            sessions.append({"start": s_start, "end": s_last, "events": count, "duration_s": int((s_last - s_start).total_seconds())})
            s_start, count = ts, 0
        s_last, count = ts, count + 1
    sessions.append({"start": s_start, "end": s_last, "events": count, "duration_s": int((s_last - s_start).total_seconds())})
    return sessions

# ═══════════════════════════════════════════════════════════════════════════════
# ── FILE & HTML REPORTING ─────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def report_csv_integrity(result: Dict, path: str) -> None:
    fields = ["type","gap_start","gap_end","duration_human", "duration_seconds","severity","start_line","end_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for g in result["gaps"]:
            w.writerow({k: g.get(k,"N/A") for k in fields})

def report_csv_behavioral(result: Dict, path: str) -> None:
    fields = ["ip","hits","span","kill_chain_score", "session_count","is_ioc","risk_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t in result["threats"]:
            w.writerow({
                "ip": t["ip"], "hits": t["hits"], "span": t["span"],
                "kill_chain_score": t["kill_chain_score"],
                "session_count": t["session_count"],
                "is_ioc": t.get("is_ioc", False),
                "risk_tags": ", ".join(t["risk_tags"]),
            })

def report_json(result: Dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

def _build_zone_breakdown_html(breakdown: Dict) -> str:
    ZONE_META = {
        "integrity":    ("⏱️ Integrity",    "Timeline gaps & reversed timestamps"),
        "access":       ("🔐 Access",        "Login failures, brute force, privilege escalation"),
        "persistence":  ("🪝 Persistence",   "Log-tampering & anti-forensic commands"),
        "privacy":      ("🔒 Privacy",       "Sensitive file & credential access"),
        "continuity":   ("💥 Continuity",    "Service crashes, kernel panics, OOM events"),
        "exfiltration": ("📤 Exfiltration",  "Data-transfer & reverse-shell indicators"),
        "lateral":      ("🌐 Lateral Mvmt",  "SSH pivoting, PsExec, remote management tools"),
    }
    rows = []
    for zone, (label, note) in ZONE_META.items():
        p   = breakdown.get(zone, 0.0)
        pct = int(p * 100)
        col = "#ef4444" if pct >= 75 else ("#f59e0b" if pct >= 40 else "#10b981" if pct > 0 else "#d1d5db")
        rows.append(f"""
  <div class="zb-row">
    <span class="zb-lbl">{label}</span>
    <div class="zb-bar-wrap"><div class="zb-bar" style="width:{pct}%;background:{col}"></div></div>
    <span class="zb-pct" style="color:{col}">{pct}%</span>
  </div>
  <div class="zb-note">{note}</div>""")
    return "\n".join(rows)

def report_html(result: Dict, filepath: str, path: str) -> None:
    risk       = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 40 else "#10b981")
    sys_info   = {"ts": datetime.now().isoformat(), "host": socket.gethostname(), "os": platform.system(), "ver": platform.release(), "arch": platform.machine(), "cpu": platform.processor()}
    perf, stats, eb = result["performance"], result["stats"], result["entropy_baseline"]
    esc = html_mod.escape

    def tag_html(label: str, color: str = "blue") -> str: return f'<span class="tag tag-{color}">{esc(label)}</span>'
    def zone_count_cls(items) -> str: return "ok" if not items else ""

    def gen_rows(subset: list) -> str:
        if not subset: return '<tr><td colspan="5" class="no-data">No threats detected in this zone.</td></tr>'
        out = []
        for t in subset:
            kc_b  = f'<span class="kc-badge">KC:{t["kill_chain_score"]}</span>' if t["kill_chain_score"] >= 2 else ""
            ioc_b = tag_html("IOC","red") if t.get("is_ioc") else ""
            tags  = " ".join(tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED","KNOWN_MALICIOUS_IOC","LOG_TAMPERING","DATA_EXFIL") else "blue") for tg in t["risk_tags"])
            out.append(f"<tr><td><strong>{esc(t['ip'])}</strong>{ioc_b}</td><td>{t['hits']}</td><td>{t['session_count']}</td><td>{kc_b}</td><td>{tags}</td></tr>")
        return "".join(out)

    def gap_rows(gtype: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gtype]
        if not subset: return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(f"<tr><td>{tag_html(g['severity'],'red')}</td><td>{esc(g.get('duration_human','N/A'))}</td><td>{g.get('start_line', 'N/A')}–{g.get('end_line', 'N/A')}</td><td>{esc(g['gap_start'][:19])}</td></tr>" for g in subset)

    priv_esc    = [t for t in result["threats"] if "PRIV_ESCALATION"     in t["risk_tags"]]
    brute_force = [t for t in result["threats"] if "BRUTE_FORCE_BURST"   in t["risk_tags"] or "FAILED_LOGIN" in t["risk_tags"]]
    distributed = [t for t in result["threats"] if "DISTRIBUTED_ATTACK"  in t["risk_tags"]]
    log_tamper  = [t for t in result["threats"] if "LOG_TAMPERING"       in t["risk_tags"]]
    exfil       = [t for t in result["threats"] if "DATA_EXFIL"          in t["risk_tags"]]
    lateral     = [t for t in result["threats"] if "LATERAL_MOVEMENT"    in t["risk_tags"]]
    kill_chain  = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    ent_hits    = [t for t in result["threats"] if "HIGH_ENTROPY_PAYLOAD" in t["risk_tags"]]
    ioc_hits    = [t for t in result["threats"] if t.get("is_ioc")]

    max_hits = max((t["hits"] for t in result["threats"]), default=1)
    actor_bars = "".join(f'<div class="actor-row"><span class="actor-ip">{esc(t["ip"])}</span><div class="actor-bar-wrap"><div class="actor-bar" style="width:{int(t["hits"]/max_hits*100)}%;background:{"#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else "#f59e0b" if t["kill_chain_score"] >= 2 else "#3b82f6"}"></div></div><span class="actor-hits">{t["hits"]}</span></div>' for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10])

    compare_html = ""
    if result.get("compare") and result["compare"]["count"]:
        compare_html = f"""<div class="card"><h3>🔄 New Actors vs Baseline</h3><p style="color:var(--secondary);font-size:13px;">{result['compare']['count']} previously unseen IPs.</p><p style="font-family:monospace;font-size:12px;word-break:break-all;">{esc(", ".join(result['compare']['new_actors'][:20]))}</p></div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{esc(PROJECT_NAME)} – {esc(os.path.basename(filepath))}</title>
<style>
:root{{--primary:#111827;--secondary:#6b7280;--danger:#ef4444;--warning:#f59e0b;--success:#10b981;--bg:#f3f4f6;--card:#ffffff;--border:#e5e7eb}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--primary);padding:24px;line-height:1.6;font-size:14px}}
.container{{max-width:1280px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.5px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px}}
h3{{font-size:15px;font-weight:700;margin-bottom:12px}}
.card{{background:var(--card);border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);padding:24px;margin-bottom:20px;border:1px solid var(--border)}}
.g2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:20px}}
.g4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:14px;margin-bottom:20px}}
.pill{{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.pill .val{{font-size:28px;font-weight:900;line-height:1}}
.pill .lbl{{font-size:11px;color:var(--secondary);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
.risk-meter{{height:48px;background:#e5e7eb;border-radius:24px;overflow:hidden;margin:12px 0;position:relative;border:1px solid var(--border)}}
.risk-fill{{height:100%;background:{risk_color};width:{risk}%}}
.risk-text{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:17px;text-shadow:0 1px 4px rgba(0,0,0,.5)}}
details{{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fafafa;overflow:hidden}}
summary{{padding:14px 18px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;border-left:4px solid var(--secondary)}}
summary::-webkit-details-marker{{display:none}}
summary::after{{content:'▼';margin-left:auto;font-size:11px;transition:transform .2s;color:var(--secondary)}}
details[open] summary::after{{transform:rotate(180deg)}}
details[open] summary{{border-left-color:var(--primary);background:#fff;border-bottom:1px solid var(--border)}}
.inner{{border:none;background:transparent;margin:8px 0;border-radius:0}}
.inner summary{{padding:10px 18px;font-size:13px;background:#f1f5f9;border-left:3px solid var(--secondary);font-weight:600}}
.tw{{padding:12px 16px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f8fafc;color:var(--secondary);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
tr:last-child td{{border:none}}tr:hover td{{background:#f9fafb}}
.tag{{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px;display:inline-block}}
.tag-red{{background:#fee2e2;color:#991b1b}}.tag-blue{{background:#dbeafe;color:#1e40af}}
.kc-badge{{background:#7c3aed;color:#fff;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;margin-left:6px}}
.no-data{{color:var(--secondary);font-style:italic;text-align:center;padding:16px}}
.story-card{{background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px;margin-bottom:20px;border-left:5px solid #38bdf8}}
.story-card p{{line-height:1.8;font-size:14px}}
.mr{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13px}}
.mr:last-child{{border:none}}.ml{{color:var(--secondary)}}.mv{{font-weight:600}}
.actor-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}}
.actor-ip{{width:130px;font-family:monospace;font-size:12px;flex-shrink:0}}
.actor-bar-wrap{{flex:1;height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden}}
.actor-bar{{height:100%;border-radius:5px}}.actor-hits{{width:50px;text-align:right;color:var(--secondary);font-size:12px}}
.ei{{font-size:12px;color:var(--secondary);padding:10px 16px;background:#f8fafc;border-bottom:1px solid var(--border)}}
.zh{{display:flex;align-items:center;gap:8px}}
.zc{{background:var(--danger);color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700}}
.zc.ok{{background:var(--success)}}
.fp{{font-family:monospace;font-size:11px;background:#f1f5f9;padding:3px 8px;border-radius:4px;color:#374151}}
footer{{text-align:center;color:var(--secondary);font-size:11px;padding:20px 0}}
.zb-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px;font-size:13px}}
.zb-lbl{{width:110px;font-weight:600;flex-shrink:0;font-size:12px}}
.zb-bar-wrap{{flex:1;height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden}}
.zb-bar{{height:100%;border-radius:7px}}.zb-pct{{width:40px;text-align:right;font-weight:700;font-size:12px}}
.zb-note{{font-size:11px;color:var(--secondary);margin-top:2px;padding-left:122px;margin-bottom:10px}}
</style>
</head><body><div class="container">

<div class="card">
  <h1>🔍 {esc(PROJECT_NAME)}</h1>
  <p style="color:var(--secondary);margin:4px 0 4px;">Forensic Audit: <strong>{esc(os.path.basename(filepath))}</strong> &nbsp;·&nbsp; {sys_info['ts'][:19]}</p>
  <p style="margin-bottom:16px;font-size:12px;color:var(--secondary);">Saved to: <span class="fp">{esc(path)}</span></p>
  <div class="risk-meter"><div class="risk-fill"></div>
  <div class="risk-text">SYSTEM COMPROMISE PROBABILITY: {risk}%</div></div>
</div>

<div class="g4">
  <div class="pill"><div class="val" style="color:{'#ef4444' if result['gaps'] else '#10b981'}">{len(result['gaps'])}</div><div class="lbl">Timeline Anomalies</div></div>
  <div class="pill"><div class="val" style="color:#f59e0b">{len(result['threats'])}</div><div class="lbl">Threat Actors</div></div>
  <div class="pill"><div class="val" style="color:#7c3aed">{len(kill_chain)}</div><div class="lbl">Kill Chains</div></div>
  <div class="pill"><div class="val" style="color:#ef4444">{len(ioc_hits)}</div><div class="lbl">IOC Matches</div></div>
  <div class="pill"><div class="val" style="color:#3b82f6">{stats['obfuscated']}</div><div class="lbl">Entropy Alerts</div></div>
  <div class="pill"><div class="val" style="color:#0891b2">{len(distributed)}</div><div class="lbl">Dist. Attackers</div></div>
  <div class="pill"><div class="val">{stats['rare_templates']}</div><div class="lbl">Rare Templates</div></div>
  <div class="pill"><div class="val" style="color:#10b981">{perf['lps']:,}</div><div class="lbl">Lines/sec</div></div>
  <div class="pill"><div class="val" style="color:#10b981">{perf['mbps']}</div><div class="lbl">MB/sec</div></div>
  <div class="pill"><div class="val">{perf['workers']}</div><div class="lbl">Workers Used</div></div>
  <div class="pill"><div class="val" style="color:#7c3aed">{perf['cpu_limit']:.0f}%</div><div class="lbl">CPU Cap/Worker</div></div>
</div>

<div class="g2">
  <div class="card">
    <h3>💻 System Metadata</h3>
    <div class="mr"><span class="ml">Hostname</span><span class="mv">{sys_info['host']}</span></div>
    <div class="mr"><span class="ml">OS</span><span class="mv">{sys_info['os']} {sys_info['ver']}</span></div>
    <div class="mr"><span class="ml">Architecture</span><span class="mv">{sys_info['arch']}</span></div>
    <div class="mr"><span class="ml">Processor</span><span class="mv">{sys_info['cpu'] or 'N/A'}</span></div>
  </div>
  <div class="card">
    <h3>📈 Analysis Intelligence</h3>
    <div class="mr"><span class="ml">Log Type</span><span class="mv">{stats['log_type']}</span></div>
    <div class="mr"><span class="ml">Throughput</span><span class="mv">{perf['lps']:,} lines/sec @ {perf['mbps']} MB/s</span></div>
    <div class="mr"><span class="ml">Processing Time</span><span class="mv">{perf['time']}s ({perf['workers']} workers, CPU cap {perf['cpu_limit']:.0f}%)</span></div>
    <div class="mr"><span class="ml">Entropy Baseline</span><span class="mv">μ={eb['mean']:.3f}  σ={eb['std']:.3f}  Θ={eb['threshold']:.3f}</span></div>
    <div class="mr"><span class="ml">Parsed / Total</span><span class="mv">{stats['parsed']:,} / {stats['total']:,}</span></div>
  </div>
</div>

<div class="story-card">
  <h3 style="margin-bottom:10px;">📖 Forensic Reconstruction</h3>
  <p>Analysis of <strong>{stats['total']:,}</strong> lines using <strong>{perf['workers']} parallel workers</strong> at <strong>{perf['mbps']} MB/s</strong> identified <strong>{len(result['threats'])}</strong> active threat entities across <strong>{len(result['gaps'])}</strong> timeline violations.
  {'<strong style="color:#f87171">Kill-chain confirmed for ' + str(len(kill_chain)) + ' actor(s).</strong>' if kill_chain else 'No kill-chain confirmed.'}
  {'<strong style="color:#fb923c"> Distributed attack: ' + str(len(distributed)) + ' IPs.</strong>' if distributed else ''}
  Peak: <strong>{max((t['hits'] for t in result['threats']), default=0):,}</strong> events from one source.
  Entropy Θ={eb['threshold']:.2f} flagged <strong>{stats['obfuscated']}</strong> obfuscated payloads.</p>
</div>

{'<div class="card"><h3>📊 Top Actor Activity</h3>' + actor_bars + '</div>' if actor_bars else ''}

{compare_html}

<div class="card">
  <h3>🎯 Risk Zone Breakdown</h3>
  <p style="color:var(--secondary);font-size:12px;margin-bottom:16px;">Per-zone probabilities computed dynamically (using asymptotic exponential smoothing) based on distinct actors and attack volumes. They compound into the headline probability.</p>
{_build_zone_breakdown_html(result.get("risk_breakdown", {}))}
</div>

<div class="card">
  <h2>📂 Categorized Forensic Evidence</h2>

  <details><summary><div class="zh">⏱️ Zone 1: Timeline &amp; Integrity<span class="zc {zone_count_cls(result['gaps'])}">{len(result['gaps'])}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Timeline Gaps</summary><table><thead><tr><th>Severity</th><th>Duration</th><th>Lines</th><th>Start</th></tr></thead><tbody>{gap_rows('GAP')}</tbody></table></details>
    <details class="inner"><summary>Reversed Timestamps</summary><table><thead><tr><th>Severity</th><th>Delta</th><th>Lines</th><th>Start</th></tr></thead><tbody>{gap_rows('REVERSED')}</tbody></table></details>
    <details class="inner"><summary>Anti-Forensic Commands</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(log_tamper)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">🔐 Zone 2: Access &amp; Control<span class="zc {zone_count_cls(brute_force + priv_esc)}">{len(brute_force)+len(priv_esc)}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Brute Force / Credential Attacks</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(brute_force)}</tbody></table></details>
    <details class="inner"><summary>Distributed Attack Participants</summary><div class="ei">Coordinated storm across {DISTRIBUTED_ATTACK_WINDOW}s windows.</div><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(distributed)}</tbody></table></details>
    <details class="inner"><summary>Privilege Escalation</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(priv_esc)}</tbody></table></details>
    <details class="inner"><summary>Lateral Movement</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(lateral)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">💀 Zone 3: Kill-Chain &amp; Confirmed Attacks<span class="zc {zone_count_cls(kill_chain)}">{len(kill_chain)}</span></div></summary>
  <div class="tw">
    <details class="inner"><summary>Kill-Chain Actors</summary><div class="ei">Stages: {' → '.join(KILL_CHAIN_STAGES)}</div><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC Score</th><th>Tags</th></tr></thead><tbody>{gen_rows(kill_chain)}</tbody></table></details>
    <details class="inner"><summary>Data Exfiltration</summary><table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead><tbody>{gen_rows(exfil)}</tbody></table></details>
  </div></details>

  <details><summary><div class="zh">🔮 Zone 4: Obfuscation &amp; Entropy<span class="zc {zone_count_cls(ent_hits)}">{len(ent_hits)}</span></div></summary>
  <div class="tw">
    <div class="ei">Dynamic Θ={eb['threshold']:.3f} (μ={eb['mean']:.3f}, σ={eb['std']:.3f}). Lines above threshold: packed/encoded payloads.</div>
    <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
    <tbody>{gen_rows(ent_hits) if ent_hits else '<tr><td colspan="5" class="no-data">None detected.</td></tr>'}</tbody></table>
  </div></details>

  <details><summary><div class="zh">🌐 Zone 5: IOC Matches<span class="zc {zone_count_cls(ioc_hits)}">{len(ioc_hits)}</span></div></summary>
  <div class="tw">
    <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
    <tbody>{gen_rows(ioc_hits) if ioc_hits else '<tr><td colspan="5" class="no-data">No IOC matches. Use --ioc-feed to enable.</td></tr>'}</tbody></table>
  </div></details>
</div>

<footer>{esc(PROJECT_NAME)} v{PROJECT_VERSION} &nbsp;|&nbsp; {stats['parsed']:,} parsed &nbsp;|&nbsp; {stats['skipped']:,} skipped &nbsp;|&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f: f.write(html_content)


# ═══════════════════════════════════════════════════════════════════════════════
# ── TERMINAL REPORTING (Restored from v2.1) ───────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET

def get_system_metadata() -> Dict:
    return {
        "os": platform.system(), "ver": platform.release(),
        "arch": platform.machine(), "host": socket.gethostname(),
        "cpu": platform.processor(), "ts": datetime.now().isoformat(),
    }

def print_banner():
    C = "\033[38;2;90;184;240m"   # Bright pixel blue (Core blocks)
    D = "\033[38;2;41;128;196m"   # Mid blue (Side/Top borders)
    S = "\033[38;2;30;77;122m"    # Shadow blue (Bottom borders)
    R = "\033[0m"                 # Reset
    
    print(f"""
  {C}██{D}╗      {C}██████{D}╗   {C}██████{D}╗ 
  {C}██{D}║     {C}██{D}╔{S}═══{C}██{D}╗ {C}██{D}╔{S}════╝ 
  {C}██{D}║     {C}██{D}║   {C}██{D}║ {C}██{D}║  {C}███{D}╗
  {C}██{D}║     {C}██{D}║   {C}██{D}║ {C}██{D}║   {C}██{D}║
  {C}███████{D}╗{S}╚{C}██████{D}╔{S}╝ {S}╚{C}██████{D}╔{S}╝
  {S}╚══════╝ ╚═════╝   ╚═════╝ {R}
                           
{C}██████{D}╗  {C}███████{D}╗ {C}████████{D}╗ {C}███████{D}╗  {C}██████{D}╗ {C}████████{D}╗  {C}██████{D}╗  {C}██████{D}╗ 
{C}██{D}╔{S}══{C}██{D}╗ {C}██{D}╔{S}════╝ {S}╚══{C}██{D}╔{S}══╝ {C}██{D}╔{S}════╝ {C}██{D}╔{S}════╝ {S}╚══{C}██{D}╔{S}══╝ {C}██{D}╔{S}═══{C}██{D}╗ {C}██{D}╔{S}══{C}██{D}╗
{C}██{D}║  {C}██{D}║ {C}█████{D}╗      {C}██{D}║    {C}█████{D}╗   {C}██{D}║         {C}██{D}║    {C}██{D}║   {C}██{D}║ {C}██████{D}╔{S}╝
{C}██{D}║  {C}██{D}║ {C}██{D}╔{S}══╝      {C}██{D}║    {C}██{D}╔{S}══╝   {C}██{D}║         {C}██{D}║    {C}██{D}║   {C}██{D}║ {C}██{D}╔{S}══{C}██{D}╗
{C}██████{D}╔{S}╝ {C}███████{D}╗    {C}██{D}║    {C}███████{D}╗ {S}╚{C}██████{D}╗    {C}██{D}║    {S}╚{C}██████{D}╔{S}╝ {C}██{D}║  {C}██{D}║
{S}╚═════╝  ╚══════╝    ╚═╝    ╚══════╝  ╚═════╝    ╚═╝     ╚═════╝  ╚═╝  ╚═╝{R}
""")

def report_terminal(result: Dict, filepath: str, out_paths: Dict[str, str]) -> None:
    risk     = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 75 else (C.YELLOW if risk >= 40 else C.GREEN)
    perf     = result["performance"]
    stats    = result["stats"]
    eb       = result["entropy_baseline"]
    sys_info = get_system_metadata()
    W = 79

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}")
    print_banner()
    print(f"\n {C.BOLD}Foreign Threat Analysis | v{PROJECT_VERSION} (Optimized){C.RESET}")
    print(f"{C.BOLD}{'━'*W}{C.RESET}")

    print(f" {C.BOLD}[SYSTEM CONTEXT]{C.RESET}               {C.BOLD}[PERFORMANCE]{C.RESET}")
    print(f"  Host : {sys_info['host']:<25} Time  : {perf['time']}s")
    print(f"  OS   : {sys_info['os']:<25} Rate  : {perf['lps']:,} lines/sec")
    print(f"  Type : {stats['log_type']:<25} Speed : {perf['mbps']} MB/s")
    print(f"  Parse: {stats['parsed']:,} / {stats['total']:,} lines"
          f"{'':<5} Workers: {perf['workers']}  CPU cap: {perf['cpu_limit']:.0f}%")

    print(f"\n {C.BOLD}[ENTROPY BASELINE]{C.RESET}")
    print(f"  Mean={eb['mean']:.3f}  StdDev={eb['std']:.3f}  "
          f"Threshold={C.YELLOW}{eb['threshold']:.3f}{C.RESET}  "
          f"(dynamic, first {ENTROPY_BASELINE_LINES} lines)")

    print(f"\n {C.BOLD}[RISK ASSESSMENT]{C.RESET}")
    print(f"  Compromise Probability: {risk_col}{C.BOLD}{risk:>3}%{C.RESET}  "
          f"{risk_col}{_bar(risk, 100, width=40)}{C.RESET}")

    breakdown    = result.get("risk_breakdown", {})
    zone_labels  = {"integrity": "Integrity   ", "access": "Access      ", "persistence": "Persistence ",
                    "privacy": "Privacy     ", "continuity": "Continuity  ", "exfiltration": "Exfiltration",
                    "lateral": "Lateral Mvmt"}
    active_zones = [(z, p) for z, p in breakdown.items() if p > 0.0]
    if active_zones:
        print(f"\n {C.BOLD}[RISK ZONES]{C.RESET}")
        for z, p in active_zones:
            pct   = int(p * 100)
            z_col = C.RED if pct >= 75 else (C.YELLOW if pct >= 40 else C.GREEN)
            print(f"  {zone_labels.get(z, z)}  {z_col}{pct:>3}%{C.RESET}  "
                  f"{z_col}{_bar(pct, 100, width=30)}{C.RESET}")

    kc_actors = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    if kc_actors:
        print(f"\n {C.BOLD}{C.RED}[⚠  KILL-CHAIN CONFIRMED]{C.RESET}")
        for kc in kc_actors[:3]:
            stage_str = " → ".join(s for s in KILL_CHAIN_STAGES if s in kc["risk_tags"])
            print(f"  {C.RED}{kc['ip']:<16}{C.RESET}  stages={kc['kill_chain_score']}  "
                  f"{C.DIM}{stage_str}{C.RESET}")

    dist = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    if dist:
        print(f"\n {C.BOLD}{C.YELLOW}[🌐 DISTRIBUTED ATTACK]{C.RESET}")
        print(f"  {len(dist)} IPs in coordinated login storm")

    print(f"\n {C.BOLD}[FORENSIC FINDINGS]{C.RESET}")
    ioc_count = sum(1 for t in result["threats"] if t.get("is_ioc"))
    print(f"  Timeline Anomalies : {C.RED if result['gaps'] else C.GREEN}{len(result['gaps']):>3} detected{C.RESET}")
    print(f"  Threat Entities    : {C.RED if len(result['threats']) > 3 else C.YELLOW}{len(result['threats']):>3} active actors{C.RESET}")
    print(f"  Obfuscated Payloads: {C.YELLOW}{stats['obfuscated']:>3}{C.RESET}")
    print(f"  Rare Templates     : {C.MAGENTA}{stats['rare_templates']:>3}{C.RESET}")
    print(f"  IOC Matches        : {C.RED if ioc_count else C.GREEN}{ioc_count:>3}{C.RESET}")
    if result.get("compare"):
        print(f"  New Actors (diff)  : {C.YELLOW}{result['compare']['count']:>3}{C.RESET}")

    if result["threats"]:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        print(f"  {'IP':<17}| {'HITS':<7}| {'KC':<4}| {'SESS':<5}| TAGS")
        print(f"  {'-'*17}+-{'-'*7}+-{'-'*4}+-{'-'*5}+-{'-'*35}")
        for t in sorted(result["threats"], key=lambda x: (x["kill_chain_score"], x["hits"]), reverse=True)[:8]:
            tags_str = ", ".join(t["risk_tags"][:3])
            ioc_flag = f" {C.RED}[IOC]{C.RESET}" if t.get("is_ioc") else ""
            kc_col   = C.RED if t["kill_chain_score"] >= 3 else C.YELLOW
            print(f"  {C.YELLOW}{t['ip']:<17}{C.RESET}| {t['hits']:<7}| "
                  f"{kc_col}{t['kill_chain_score']:<4}{C.RESET}| "
                  f"{t['session_count']:<5}| {C.GREY}{tags_str}{C.RESET}{ioc_flag}")

    if result["gaps"]:
        print(f"\n {C.BOLD}[TIMELINE ANOMALIES]{C.RESET}")
        print(f"  {'TYPE':<10} {'SEVERITY':<10} {'DURATION':<20} LINES")
        print(f"  {'-'*10} {'-'*10} {'-'*20} {'-'*12}")
        for g in result["gaps"][:6]:
            sev_col = C.RED if g["severity"] == "CRITICAL" else C.YELLOW
            print(f"  {g['type']:<10} {sev_col}{g['severity']:<10}{C.RESET} "
                  f"{g.get('duration_human','N/A'):<20} "
                  f"{g.get('start_line', 'N/A')}-{g.get('end_line', 'N/A')}")

   

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}\n")

# ═══════════════════════════════════════════════════════════════════════════════
# ── MAIN ORCHESTRATOR ─────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def scan_log(filepath, threshold_seconds, ioc_set=frozenset(), compare_filepath=None, n_workers=1, cpu_limit_pct=25.0, sigs=()) -> Dict:
    t_start = time.monotonic()
    is_compressed = filepath.endswith((".gz", ".bz2"))
    
    # Baseline
    baseline_lines = []
    opener = (gzip.open if filepath.endswith(".gz") else bz2.open) if is_compressed else open
    mode = "rt" if is_compressed else "r"
    try:
        with opener(filepath, mode, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= ENTROPY_BASELINE_LINES: break
                baseline_lines.append(line)
    except: pass
    eb_mean, eb_std = compute_entropy_baseline(baseline_lines)
    eb_thresh = max(ENTROPY_ABS_MIN, eb_mean + ENTROPY_STD_MULTIPLIER * eb_std)

    mp_ctx = multiprocessing.get_context("spawn")
    rq = mp_ctx.Queue()
    procs = []

    if is_compressed:
        p = mp_ctx.Process(target=_worker_compressed, args=(filepath, threshold_seconds, ioc_set, eb_thresh, rq, cpu_limit_pct, sigs))
        p.start(); procs.append(p); n_expected = 1
    else:
        # File chunking logic (Preserved)
        size = os.path.getsize(filepath)
        chunk_size = max(CHUNK_MIN_BYTES, size // n_workers)
        chunks = []
        start = 0
        with open(filepath, "rb") as fh:
            while start < size:
                end = min(start + chunk_size, size)
                if end < size:
                    fh.seek(end); remainder = fh.read(4096); nl = remainder.find(b"\n")
                    end = end + nl + 1 if nl != -1 else size
                chunks.append((start, end)); start = end
        n_expected = len(chunks)
        for s, e in chunks:
            p = mp_ctx.Process(target=_worker, args=(filepath, s, e, threshold_seconds, ioc_set, eb_thresh, rq, cpu_limit_pct, sigs))
            p.start(); procs.append(p)

    merged_gaps, merged_ip_stats, merged_templates, total_lines, parsed_lines, obfuscated_cnt, log_type = [], {}, Counter(), 0, 0, 0, None
    time_buckets = defaultdict(list)
    
    for _ in range(n_expected):
        res = rq.get()
        if "error" in res: continue
        merged_gaps.extend(res["gaps"])
        total_lines += res["total_lines"]; parsed_lines += res["parsed_lines"]; obfuscated_cnt += res["obfuscated_count"]
        log_type = log_type or res["log_type"]
        merged_templates.update(res["template_counts"])
        for bucket_key, events in res["time_buckets"].items():
            time_buckets[bucket_key].extend(events)
        for ip, s in res["ip_stats"].items():
            if ip not in merged_ip_stats: merged_ip_stats[ip] = s
            else:
                merged_ip_stats[ip]["hits"] += s["hits"]; merged_ip_stats[ip]["tags"].update(s["tags"])
                merged_ip_stats[ip]["events"].extend(s["events"])

    for p in procs: p.join()

    # Determine Distributed attacks
    distributed_ips = set()
    for bucket, events in time_buckets.items():
        fail_events = [(ip, f) for ip, f in events if f]
        unique_fail = set(ip for ip, _ in fail_events)
        if len(fail_events) >= DISTRIBUTED_FAIL_THRESHOLD and len(unique_fail) >= 3:
            distributed_ips.update(unique_fail)

    final_threats = []
    for ip, s in merged_ip_stats.items():
        fails = sorted([e for e in s["events"] if "FAILED_LOGIN" in s["tags"]]) # Rough estimate for timing
        
        if len(fails) >= BRUTE_FORCE_THRESHOLD:
            if (fails[-1] - fails[0]).total_seconds() < (BRUTE_FORCE_WINDOW_MIN * 60):
                s["tags"].add("BRUTE_FORCE_BURST")

        if ip in distributed_ips: s["tags"].add("DISTRIBUTED_ATTACK")
        
        kc_score = len(s["tags"] & set(KILL_CHAIN_STAGES))
        if kc_score >= 3: s["tags"].add("KILL_CHAIN_DETECTED")

        if s["tags"] or s["hits"] > 200:
            events_sorted = sorted(s["events"])
            final_threats.append({
                "ip": ip,
                "hits": s["hits"],
                "risk_tags": sorted(list(s["tags"])),
                "kill_chain_score": kc_score,
                "session_count": len(session_reconstruct(events_sorted)),
                "span": str(events_sorted[-1] - events_sorted[0]) if events_sorted else "0:00:00",
                "is_ioc": "KNOWN_MALICIOUS_IOC" in s["tags"]
            })

    # Compare Baseline
    compare_result = None
    if compare_filepath and os.path.isfile(compare_filepath):
        new_ips = set()
        try:
            with open(compare_filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = IP_RE.search(line)
                    if m and m.group() not in merged_ip_stats: new_ips.add(m.group())
        except: pass
        compare_result = {"new_actors": sorted(new_ips), "count": len(new_ips)}

    proc_time = time.monotonic() - t_start
    return {
        "gaps": merged_gaps, 
        "threats": final_threats, 
        "risk_breakdown": _risk_zones(merged_gaps, final_threats),
        "performance": {
            "time": round(proc_time, 2), 
            "lps": int(total_lines/proc_time) if proc_time > 0 else 0, 
            "mbps": round((os.path.getsize(filepath)/1e6)/proc_time, 1) if proc_time > 0 else 0,
            "workers": n_workers, "cpu_limit": cpu_limit_pct
        },
        "stats": {
            "total": total_lines, "parsed": parsed_lines, "skipped": total_lines - parsed_lines, 
            "obfuscated": obfuscated_cnt, "log_type": log_type or "Unknown",
            "rare_templates": sum(1 for c in merged_templates.values() if c <= RARE_TEMPLATE_THRESHOLD)
        },
        "entropy_baseline": {"mean": eb_mean, "std": eb_std, "threshold": eb_thresh},
        "compare": compare_result
    }

def main():
    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser(description=f"{PROJECT_NAME} v{PROJECT_VERSION}")
    parser.add_argument("logfile", help="Log file path (.log / .gz / .bz2)")
    parser.add_argument("--threshold", "-t", type=float, default=300.0, help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--ioc-feed", type=str, default=None, help="Newline-delimited known-bad IP list")
    parser.add_argument("--compare", type=str, default=None, help="Second log for comparative actor profiling")
    parser.add_argument("--workers", "-w", type=int, default=None, help="Worker processes (default: 50% of CPU threads)")
    parser.add_argument("--cpu-limit", "-c", type=float, default=25.0, help="Max CPU % per worker process (default: 25)")
    parser.add_argument("--format", "-f", choices=["all", "terminal", "json", "csv", "html"], default="all", help="Output formats")
    args = parser.parse_args()

    sigs = load_sigs()
    ioc_set = set()
    if args.ioc_feed and os.path.exists(args.ioc_feed):
        with open(args.ioc_feed, 'r') as f:
            for line in f:
                if IP_RE.match(line.strip()): ioc_set.add(line.strip())
    
    # 1. Get the dictionary of output directories
    out_dirs = resolve_output_dir()
    out_paths = make_output_paths(out_dirs)
    n_workers = args.workers or max(1, (os.cpu_count() or 2) // 2)

    # 2. Get a clean string for the base output folder to print to the terminal
    base_doc_path = os.path.join(os.path.expanduser("~"), "Documents", REPORT_ROOT_DIR)

    print(f"\n{C.CYAN}[*] {PROJECT_NAME} v{PROJECT_VERSION}{C.RESET}")
    print(f"{C.DIM}[*] Output folder : {base_doc_path}{C.RESET}")
    print(f"{C.DIM}[*] Scanning      : {args.logfile}{C.RESET}\n")

    result = scan_log(
        args.logfile, 
        args.threshold, 
        ioc_set=frozenset(ioc_set), 
        compare_filepath=args.compare,
        n_workers=n_workers, 
        cpu_limit_pct=args.cpu_limit, 
        sigs=sigs
    )
    
    fmt = args.format
    
    # 3. UNCOMMENTED: Actually generate the reports!
    if fmt in ("all", "terminal"):
        report_terminal(result, args.logfile, out_paths)
    if fmt in ("all", "csv"):
        report_csv_integrity(result, out_paths["csv_integrity"])
        report_csv_behavioral(result, out_paths["csv_behavioral"])
    if fmt in ("all", "html"):
        report_html(result, args.logfile, out_paths["html"])
    if fmt in ("all", "json"):
        report_json(result, out_paths["json"])

    if fmt != "terminal":
        # 4. Use base_doc_path instead of out_dirs to avoid printing a raw dictionary
        print(f"\n{C.BOLD}{C.GREEN}[✓] All reports → {base_doc_path}{C.RESET}")
        print(f"    📁 {to_file_url(out_paths['csv_integrity'])}")
        print(f"    📁 {to_file_url(out_paths['csv_behavioral'])}")
        print(f"    🌐 {to_file_url(out_paths['html'])}")
        print(f"    📄 {to_file_url(out_paths['json'])}\n")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Evidence Protector v6.0 – Advanced Forensic Inference Engine
Damage-Matrix Assessment with Shannon Entropy, Kill-Chain Correlation,
Distributed Attack Detection, Session Reconstruction, and Dynamic Baselines.

Output uses hierarchical storage (Documents/Forensic_Reports/) with
auto-incrementing filenames and clickable file:// URIs.
"""

import argparse
import csv
import json
import os
import re
import sys
import gzip
import bz2
import platform
import time
import socket
import math
import html
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set
from collections import deque, Counter, defaultdict

# ── ANSI colour codes ────────────────────────────────────────────────────────
USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

class C:
    RESET   = "\033[0m"   if USE_COLOUR else ""
    BOLD    = "\033[1m"   if USE_COLOUR else ""
    RED     = "\033[91m"  if USE_COLOUR else ""
    YELLOW  = "\033[93m"  if USE_COLOUR else ""
    CYAN    = "\033[96m"  if USE_COLOUR else ""
    GREEN   = "\033[92m"  if USE_COLOUR else ""
    GREY    = "\033[90m"  if USE_COLOUR else ""
    DIM     = "\033[2m"   if USE_COLOUR else ""
    MAGENTA = "\033[95m"  if USE_COLOUR else ""
    BLUE    = "\033[94m"  if USE_COLOUR else ""

# ── Pre-compiled Regex Patterns ───────────────────────────────────────────────
IP_PATTERN    = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
TS_STRIP_PAT  = re.compile(r"^\S+\s+\S+\s+")   # strip leading timestamp tokens

# ── Kill-Chain Stage Definitions (ordered) ────────────────────────────────────
KILL_CHAIN_STAGES = [
    "SCANNING",
    "FAILED_LOGIN",
    "PRIV_ESCALATION",
    "SENSITIVE_ACCESS",
    "LOG_TAMPERING",
]

# ── Attack Signatures ─────────────────────────────────────────────────────────
ATTACK_SIGNATURES = {
    "FAILED_LOGIN":    re.compile(
        r"failed|invalid user|auth fail|password|denied|incorrect|"
        r"authentication failure|bad password|login failed", re.I),
    "PRIV_ESCALATION": re.compile(
        r"sudo|su -|privilege|elevated|root|uid=0|chmod 777|"
        r"visudo|pkexec|doas|newgrp", re.I),
    "SCANNING":        re.compile(
        r"nmap|scan|probe|port|sqli|xss|select.*from|union.*select|"
        r"nikto|masscan|zmap|dirbuster|gobuster|ffuf|nuclei|"
        r"(?:GET|POST|HEAD)\s+/\S*\?.*=", re.I),
    "LOG_TAMPERING":   re.compile(
        r"rm .*log|truncate|shred|history -c|clear-log|killall -9 syslogd|"
        r"echo.*>.*\.log|> /var/log|unlink.*log|wipe|auditctl -e 0", re.I),
    "SENSITIVE_ACCESS": re.compile(
        r"/etc/shadow|/etc/passwd|\.ssh/|id_rsa|config\.php|\.env|"
        r"/proc/self|/root/\.|lsass|SAM database|\.htpasswd|"
        r"wp-config\.php|database\.yml", re.I),
    "SERVICE_EVENTS":  re.compile(
        r"restarted|shutdown|panic|segfault|crashed|oom-killer|"
        r"kernel: BUG|double free|use-after-free|stack smashing", re.I),
    "DATA_EXFIL":      re.compile(
        r"curl.*http|wget.*http|nc -e|/dev/tcp|base64.*decode|"
        r"python.*socket|powershell.*download|certutil.*url", re.I),
    "LATERAL_MOVEMENT": re.compile(
        r"ssh.*@|scp |rsync |psexec|wmic|net use \\\\|"
        r"xfreerdp|rdesktop|winrm|evil-winrm|impacket", re.I),
}

# ── Timestamp Regexes ─────────────────────────────────────────────────────────
TIMESTAMP_REGEXES = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
     ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
      "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"], "ISO-8601"),
    (re.compile(r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"),
     ["[%d/%b/%Y:%H:%M:%S %z]"], "Web (Apache/Nginx)"),
    (re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
     ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"], "Linux Syslog"),
    (re.compile(r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"),
     ["%m/%d/%Y %H:%M:%S"], "Windows Event"),
    (re.compile(r"\d{10,13}"),
     None, "Unix Epoch"),
]

# ── Tunable Parameters ────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD     = 5
BRUTE_FORCE_WINDOW_MIN    = 10
DISTRIBUTED_ATTACK_WINDOW = 300          # 5 min bucket for distributed detection
DISTRIBUTED_FAIL_THRESHOLD = 15         # total fails across IPs in window
SESSION_INACTIVITY_SEC    = 1800        # 30 min = new session
ENTROPY_BASELINE_LINES    = 500         # lines used to calibrate entropy baseline
ENTROPY_STD_MULTIPLIER    = 2.0         # stddev multiplier for dynamic threshold
ENTROPY_ABS_MIN           = 4.5        # never flag below this regardless of baseline
RARE_TEMPLATE_THRESHOLD   = 2           # log template seen ≤ this is "rare"
CURRENT_YEAR              = datetime.now().year


# ═══════════════════════════════════════════════════════════════════════════════
# ── PATH / STORAGE HELPERS ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_report_root() -> Path:
    """
    Return (and create) the root output directory.
    Prefers ~/Documents/Forensic_Reports; falls back to ./reports if
    Documents is missing or read-only.
    """
    primary = Path.home() / "Documents" / "Forensic_Reports"
    try:
        primary.mkdir(parents=True, exist_ok=True)
        return primary
    except Exception:
        fallback = Path.cwd() / "reports"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def get_next_filename(folder: Path, prefix: str, extension: str) -> Path:
    """
    Return the next auto-incrementing Path that does not yet exist.
    e.g. integrity_report1.csv → integrity_report2.csv → …
    """
    i = 1
    while (folder / f"{prefix}{i}.{extension}").exists():
        i += 1
    return folder / f"{prefix}{i}.{extension}"


def _file_uri(path: Path) -> str:
    """Return a clickable file:// URI that works on all platforms."""
    return f"file://{path.resolve().as_posix()}"


# ═══════════════════════════════════════════════════════════════════════════════
# ── INTELLIGENCE FUNCTIONS ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def calculate_entropy(data: str) -> float:
    """Shannon Entropy calculation after stripping known-good tokens."""
    if not data or len(data) < 10:
        return 0.0
    clean = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\w:+-]*", "", data)
    clean = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "", clean)
    clean = clean.strip()
    if len(clean) < 8:
        return 0.0
    counts = Counter(clean)
    length = len(clean)
    return sum(-(c / length) * math.log(c / length, 2) for c in counts.values())


def compute_entropy_baseline(lines: List[str]) -> Tuple[float, float]:
    """Compute mean and stddev of entropy from a sample of lines."""
    values = [calculate_entropy(l) for l in lines if l.strip()]
    if not values:
        return 5.0, 0.5
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(variance)


def log_template(line: str) -> str:
    """Reduce a log line to its structural template by masking variables."""
    t = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", line)
    t = re.sub(r"\b\d+\b", "<N>", t)
    t = re.sub(r'["\'].*?["\']', "<STR>", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:120]


def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse timestamp from a log line, supporting multiple formats."""
    now = datetime.now()
    for regex, fmts, label in TIMESTAMP_REGEXES:
        m = regex.search(line)
        if not m:
            continue
        raw = m.group()

        if label == "Unix Epoch" and fmts is None:
            try:
                epoch = int(raw[:10])
                return datetime.fromtimestamp(epoch), label
            except (ValueError, OSError, OverflowError):
                continue

        clean = re.sub(r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$", "", raw.strip("[]")).strip()
        for fmt in fmts:
            try:
                if "%Y" not in fmt:
                    dt = datetime.strptime(f"{CURRENT_YEAR} {clean}", f"%Y {fmt}")
                    if dt > now + timedelta(days=1):
                        dt = dt.replace(year=CURRENT_YEAR - 1)
                else:
                    dt = datetime.strptime(clean, fmt)
                return dt, label
            except ValueError:
                continue
    return None, None


def detect_kill_chain(tags: Set[str]) -> int:
    """Return how many sequential kill-chain stages are present (0-5)."""
    return sum(1 for stage in KILL_CHAIN_STAGES if stage in tags)


def session_reconstruct(events: List[datetime]) -> List[Dict]:
    """Group events into sessions based on inactivity window."""
    if not events:
        return []
    sessions = []
    s_start = events[0]
    s_last  = events[0]
    count   = 1
    for ts in events[1:]:
        if (ts - s_last).total_seconds() > SESSION_INACTIVITY_SEC:
            sessions.append({"start": s_start, "end": s_last, "events": count,
                             "duration_s": int((s_last - s_start).total_seconds())})
            s_start = ts
            count   = 0
        s_last = ts
        count += 1
    sessions.append({"start": s_start, "end": s_last, "events": count,
                     "duration_s": int((s_last - s_start).total_seconds())})
    return sessions


def _risk_score(gaps: list, threats: list) -> int:
    """Probabilistic Saturation Model across damage zones."""
    if not gaps and not threats:
        return 0
    zone_probs = {
        "integrity":   0.0,
        "access":      0.0,
        "persistence": 0.0,
        "privacy":     0.0,
        "continuity":  0.0,
        "exfiltration":0.0,
        "lateral":     0.0,
    }

    if any(g["type"] == "REVERSED" for g in gaps):
        zone_probs["integrity"] = 0.95
    elif any(g["severity"] == "CRITICAL" for g in gaps):
        zone_probs["integrity"] = 0.80
    elif gaps:
        zone_probs["integrity"] = 0.50

    for t in threats:
        tags = set(t["risk_tags"])
        kc   = t.get("kill_chain_score", 0)
        kc_boost = min(kc * 0.08, 0.30)

        if "PRIV_ESCALATION" in tags:
            zone_probs["access"] = max(zone_probs["access"], 0.90 + kc_boost)
        if "BRUTE_FORCE_BURST" in tags:
            zone_probs["access"] = max(zone_probs["access"], 0.70 + kc_boost)
        if "DISTRIBUTED_ATTACK" in tags:
            zone_probs["access"] = max(zone_probs["access"], 0.80)
        if "LOG_TAMPERING" in tags:
            zone_probs["persistence"] = max(zone_probs["persistence"], 0.99)
        if "SENSITIVE_ACCESS" in tags:
            zone_probs["privacy"] = max(zone_probs["privacy"], 0.85 + kc_boost)
        if "SERVICE_EVENTS" in tags:
            zone_probs["continuity"] = max(zone_probs["continuity"], 0.60)
        if "DATA_EXFIL" in tags:
            zone_probs["exfiltration"] = max(zone_probs["exfiltration"], 0.92)
        if "LATERAL_MOVEMENT" in tags:
            zone_probs["lateral"] = max(zone_probs["lateral"], 0.85)
        if "KILL_CHAIN_DETECTED" in tags:
            for z in zone_probs:
                if zone_probs[z] > 0:
                    zone_probs[z] = min(zone_probs[z] + 0.10, 0.99)

    combined_safe = 1.0
    for p in zone_probs.values():
        combined_safe *= (1.0 - p)
    return min(int((1.0 - combined_safe) * 100), 99)


# ═══════════════════════════════════════════════════════════════════════════════
# ── CORE ANALYSIS ENGINE ─────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _open_log(filepath: str):
    """Open plain, gzip, or bz2 log files transparently."""
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
    if filepath.endswith(".bz2"):
        return bz2.open(filepath, "rt", encoding="utf-8", errors="replace")
    return open(filepath, "r", encoding="utf-8", errors="replace")


def load_ioc_feed(ioc_path: Optional[str]) -> Set[str]:
    """Load known-bad IPs from a newline-delimited IOC feed file."""
    if not ioc_path or not os.path.isfile(ioc_path):
        return set()
    known_bad = set()
    with open(ioc_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and IP_PATTERN.match(line):
                known_bad.add(line)
    return known_bad


def scan_log(filepath: str, threshold_seconds: float,
             ioc_set: Set[str] = None, compare_filepath: str = None):
    """
    Main analysis pass. Returns a structured result dict.
    """
    start_time = time.time()
    if ioc_set is None:
        ioc_set = set()

    # ── Phase 0: Entropy Baseline Calibration ────────────────────────────────
    baseline_lines = []
    try:
        with _open_log(filepath) as fh:
            for i, line in enumerate(fh):
                if i >= ENTROPY_BASELINE_LINES:
                    break
                baseline_lines.append(line.rstrip("\n"))
    except Exception as e:
        print(f"[!] Baseline read error: {e}")

    entropy_mean, entropy_std = compute_entropy_baseline(baseline_lines)
    entropy_threshold = max(ENTROPY_ABS_MIN, entropy_mean + ENTROPY_STD_MULTIPLIER * entropy_std)

    # ── Phase 1: Main Analysis Pass ──────────────────────────────────────────
    gaps            = []
    total_lines     = 0
    parsed_lines    = 0
    skipped_lines   = 0
    prev_ts         = None
    first_ts        = None
    last_ts         = None
    ip_stats        = {}
    template_counts = Counter()
    obfuscated_count = 0
    log_type        = None

    time_buckets: Dict[int, List[Tuple[str, bool]]] = defaultdict(list)

    try:
        with _open_log(filepath) as fh:
            for line_no, line in enumerate(fh, start=1):
                total_lines += 1
                line_content = line.rstrip("\n")

                ts, ltype = parse_timestamp(line_content)
                if not ts:
                    skipped_lines += 1
                    continue

                parsed_lines += 1
                if log_type is None:
                    log_type = ltype
                if not first_ts:
                    first_ts = ts
                last_ts = ts

                # ── Integrity Check ──────────────────────────────────────────
                if prev_ts is not None:
                    diff = (ts - prev_ts).total_seconds()
                    if diff >= threshold_seconds:
                        gaps.append({
                            "type": "GAP",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end": ts.isoformat(),
                            "duration_human": str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity": "CRITICAL" if diff > 3600 else "HIGH",
                            "start_line": line_no - 1,
                            "end_line": line_no,
                        })
                    elif diff < -10:
                        gaps.append({
                            "type": "REVERSED",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end": ts.isoformat(),
                            "duration_human": str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity": "CRITICAL",
                            "start_line": line_no - 1,
                            "end_line": line_no,
                        })

                # ── Rare Template Detection ──────────────────────────────────
                tmpl = log_template(line_content)
                template_counts[tmpl] += 1

                # ── Entity Profiling ─────────────────────────────────────────
                ip_match = IP_PATTERN.search(line_content)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ip_stats:
                        ip_stats[ip] = {
                            "first": ts,
                            "last":  ts,
                            "hits":  0,
                            "fails": deque(maxlen=50),
                            "events": [],
                            "tags": set(),
                        }

                    stats = ip_stats[ip]
                    stats["hits"] += 1
                    stats["last"] = ts
                    stats["events"].append(ts)

                    is_fail = False
                    for tag, sig in ATTACK_SIGNATURES.items():
                        if sig.search(line_content):
                            stats["tags"].add(tag)
                            if tag == "FAILED_LOGIN":
                                stats["fails"].append(ts)
                                is_fail = True

                    if ip in ioc_set:
                        stats["tags"].add("KNOWN_MALICIOUS_IOC")

                    ent = calculate_entropy(line_content)
                    if ent > entropy_threshold:
                        stats["tags"].add("HIGH_ENTROPY_PAYLOAD")
                        obfuscated_count += 1

                    bucket_key = int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)
                    time_buckets[bucket_key].append((ip, is_fail))

                prev_ts = ts

    except Exception as e:
        print(f"[!] Fatal scan error: {e}")
        sys.exit(1)

    # ── Phase 2: Post-Analysis Enrichment ────────────────────────────────────
    rare_templates = {t for t, c in template_counts.items() if c <= RARE_TEMPLATE_THRESHOLD}

    distributed_attack_ips: Set[str] = set()
    for bucket, events in time_buckets.items():
        fail_events    = [(ip, f) for ip, f in events if f]
        unique_fail_ips = set(ip for ip, _ in fail_events)
        if len(fail_events) >= DISTRIBUTED_FAIL_THRESHOLD and len(unique_fail_ips) >= 3:
            distributed_attack_ips.update(unique_fail_ips)

    final_threats = []
    for ip, s in ip_stats.items():
        if len(s["fails"]) >= BRUTE_FORCE_THRESHOLD:
            window = (s["fails"][-1] - s["fails"][0]).total_seconds()
            if window < (BRUTE_FORCE_WINDOW_MIN * 60):
                s["tags"].add("BRUTE_FORCE_BURST")

        if ip in distributed_attack_ips:
            s["tags"].add("DISTRIBUTED_ATTACK")

        kc_score = detect_kill_chain(s["tags"])
        if kc_score >= 3:
            s["tags"].add("KILL_CHAIN_DETECTED")

        events_sorted = sorted(s["events"])
        sessions = session_reconstruct(events_sorted)

        if s["tags"] or s["hits"] > 200:
            final_threats.append({
                "ip":              ip,
                "risk_tags":       sorted(list(s["tags"])),
                "hits":            s["hits"],
                "span":            str(s["last"] - s["first"]),
                "sessions":        sessions,
                "session_count":   len(sessions),
                "kill_chain_score":kc_score,
                "is_ioc":          ip in ioc_set,
            })

    compare_result = None
    if compare_filepath and os.path.isfile(compare_filepath):
        compare_result = _compare_profile(compare_filepath, ip_stats)

    proc_time = time.time() - start_time

    return {
        "gaps":     gaps,
        "threats":  final_threats,
        "performance": {
            "time": round(proc_time, 3),
            "lps":  int(total_lines / proc_time) if proc_time > 0 else 0,
        },
        "stats": {
            "total":       total_lines,
            "parsed":      parsed_lines,
            "skipped":     skipped_lines,
            "obfuscated":  obfuscated_count,
            "log_type":    log_type or "Mixed/Unknown",
            "rare_templates": len(rare_templates),
            "distributed_windows": len([b for b in time_buckets.values()
                                        if len([e for e in b if e[1]]) >= DISTRIBUTED_FAIL_THRESHOLD]),
        },
        "entropy_baseline": {
            "mean":      round(entropy_mean, 3),
            "std":       round(entropy_std, 3),
            "threshold": round(entropy_threshold, 3),
        },
        "compare": compare_result,
    }


def _compare_profile(filepath2: str, baseline_ip_stats: Dict) -> Dict:
    """
    Light second-pass comparison: returns IPs present in file2 but not in baseline.
    """
    new_ips = set()
    try:
        with _open_log(filepath2) as fh:
            for line in fh:
                m = IP_PATTERN.search(line)
                if m:
                    ip = m.group()
                    if ip not in baseline_ip_stats:
                        new_ips.add(ip)
    except Exception:
        pass
    return {"new_actors": sorted(list(new_ips)), "count": len(new_ips)}


# ═══════════════════════════════════════════════════════════════════════════════
# ── TERMINAL OUTPUT ───────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _bar(value: int, max_val: int, width: int = 30, char: str = "█") -> str:
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET


def _human_duration(seconds: float) -> str:
    seconds = abs(int(seconds))
    if seconds < 60:   return f"{seconds}s"
    if seconds < 3600: m, s = divmod(seconds, 60); return f"{m}m {s}s"
    h, rem = divmod(seconds, 3600); return f"{h}h {rem // 60}m"


def get_system_metadata() -> Dict:
    return {
        "os":   platform.system(),
        "ver":  platform.release(),
        "arch": platform.machine(),
        "host": socket.gethostname(),
        "cpu":  platform.processor(),
        "ts":   datetime.now().isoformat(),
    }


def report_terminal(result: dict, filepath: str):
    risk     = _risk_score(result["gaps"], result["threats"])
    risk_col = C.RED if risk >= 75 else (C.YELLOW if risk >= 40 else C.GREEN)
    perf     = result["performance"]
    stats    = result["stats"]
    eb       = result["entropy_baseline"]
    sys_info = get_system_metadata()

    W = 79
    print(f"\n{C.BOLD}{'━'*W}{C.RESET}")
    print(f" {C.CYAN}🛡️  EVIDENCE PROTECTOR v6.0{C.RESET} | {C.BOLD}Forensic Inference Engine{C.RESET}")
    print(f"{C.BOLD}{'━'*W}{C.RESET}")

    print(f" {C.BOLD}[SYSTEM CONTEXT]{C.RESET}               {C.BOLD}[PERFORMANCE]{C.RESET}")
    print(f"  Host : {sys_info['host']:<25} Time  : {perf['time']}s")
    print(f"  OS   : {sys_info['os']:<25} Rate  : {perf['lps']:,} lines/sec")
    print(f"  Type : {stats['log_type']:<25} Parse : {stats['parsed']:,} / {stats['total']:,}")

    print(f"\n {C.BOLD}[ENTROPY BASELINE]{C.RESET}")
    print(f"  Mean={eb['mean']:.3f}  StdDev={eb['std']:.3f}  "
          f"Dynamic Threshold={C.YELLOW}{eb['threshold']:.3f}{C.RESET}  "
          f"(calibrated on first {ENTROPY_BASELINE_LINES} lines)")

    print(f"\n {C.BOLD}[RISK ASSESSMENT]{C.RESET}")
    print(f"  Probability of Compromise: {risk_col}{C.BOLD}{risk:>3}%{C.RESET}  "
          f"{risk_col}{_bar(risk, 100, width=42)}{C.RESET}")

    kc_actors = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    if kc_actors:
        print(f"\n {C.BOLD}{C.RED}[⚠  KILL-CHAIN CONFIRMED]{C.RESET}")
        for kc in kc_actors[:3]:
            stage_str = " → ".join(s for s in KILL_CHAIN_STAGES if s in kc["risk_tags"])
            print(f"  {C.RED}{kc['ip']:<16}{C.RESET}  stages={kc['kill_chain_score']}  {C.DIM}{stage_str}{C.RESET}")

    dist_actors = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    if dist_actors:
        print(f"\n {C.BOLD}{C.YELLOW}[🌐 DISTRIBUTED ATTACK DETECTED]{C.RESET}")
        print(f"  {len(dist_actors)} IPs participated in coordinated login storm")

    print(f"\n {C.BOLD}[FORENSIC FINDINGS]{C.RESET}")
    gap_col    = C.RED if result["gaps"] else C.GREEN
    threat_col = C.RED if len(result["threats"]) > 3 else (C.YELLOW if result["threats"] else C.GREEN)
    ioc_count  = sum(1 for t in result["threats"] if t.get("is_ioc"))

    print(f"  Timeline Integrity  : {gap_col}{len(result['gaps']):>3} anomalies detected{C.RESET}")
    print(f"  Threat Entities     : {threat_col}{len(result['threats']):>3} active actors{C.RESET}")
    print(f"  Obfuscation Markers : {C.YELLOW}{stats['obfuscated']:>3} suspicious payloads{C.RESET}")
    print(f"  Rare Log Templates  : {C.MAGENTA}{stats['rare_templates']:>3} anomalous structures{C.RESET}")
    print(f"  IOC Feed Matches    : {C.RED if ioc_count else C.GREEN}{ioc_count:>3} known-malicious IPs{C.RESET}")
    if result.get("compare"):
        print(f"  New Actors vs Baseline : {C.YELLOW}{result['compare']['count']:>3} previously unseen IPs{C.RESET}")

    if result["threats"]:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        header = f"  {'ENTITY (IP)':<17}| {'HITS':<7}| {'KC':<4}| {'SESS':<5}| RISK INDICATORS"
        print(header)
        print(f"  {'-'*17}+-{'-'*7}+-{'-'*4}+-{'-'*5}+-{'-'*38}")
        sorted_threats = sorted(result["threats"],
                                key=lambda x: (x["kill_chain_score"], x["hits"]), reverse=True)
        for t in sorted_threats[:8]:
            tags_str = ", ".join(t["risk_tags"][:3])
            ioc_flag = f" {C.RED}[IOC]{C.RESET}" if t.get("is_ioc") else ""
            kc_col   = C.RED if t["kill_chain_score"] >= 3 else C.YELLOW
            print(f"  {C.YELLOW}{t['ip']:<17}{C.RESET}| {t['hits']:<7}| "
                  f"{kc_col}{t['kill_chain_score']:<4}{C.RESET}| "
                  f"{t['session_count']:<5}| {C.GREY}{tags_str}{C.RESET}{ioc_flag}")

    if result["gaps"]:
        print(f"\n {C.BOLD}[TIMELINE ANOMALIES]{C.RESET}")
        print(f"  {'TYPE':<10} {'SEVERITY':<10} {'DURATION':<20} LINES")
        print(f"  {'-'*10} {'-'*10} {'-'*20} {'-'*15}")
        for g in result["gaps"][:6]:
            sev_col = C.RED if g["severity"] == "CRITICAL" else C.YELLOW
            print(f"  {g['type']:<10} {sev_col}{g['severity']:<10}{C.RESET} "
                  f"{g.get('duration_human', 'N/A'):<20} {g['start_line']}-{g['end_line']}")

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ── CSV / JSON / HTML OUTPUT  (now path-aware) ────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def report_csv_integrity(result: dict, report_dir: Path) -> Path:
    """Write timeline-gap CSV; returns the Path of the created file."""
    folder = report_dir / "csv"
    folder.mkdir(parents=True, exist_ok=True)
    out = get_next_filename(folder, "integrity_report", "csv")

    fields = ["type", "gap_start", "gap_end", "duration_human",
              "duration_seconds", "severity", "start_line", "end_line"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for g in result["gaps"]:
            writer.writerow({k: g.get(k, "N/A") for k in fields})
    return out


def report_csv_behavioral(result: dict, report_dir: Path) -> Path:
    """Write threat-actor CSV; returns the Path of the created file."""
    folder = report_dir / "csv"
    folder.mkdir(parents=True, exist_ok=True)
    out = get_next_filename(folder, "threat_actors", "csv")

    fields = ["ip", "hits", "span", "kill_chain_score",
              "session_count", "is_ioc", "risk_tags"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for t in result["threats"]:
            writer.writerow({
                "ip":               t["ip"],
                "hits":             t["hits"],
                "span":             t["span"],
                "kill_chain_score": t["kill_chain_score"],
                "session_count":    t["session_count"],
                "is_ioc":           t.get("is_ioc", False),
                "risk_tags":        ", ".join(t["risk_tags"]),
            })
    return out


def report_json(result: dict, report_dir: Path) -> Path:
    """Write JSON export; returns the Path of the created file."""
    folder = report_dir / "json"
    folder.mkdir(parents=True, exist_ok=True)
    out = get_next_filename(folder, "forensic_data", "json")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return out


def report_html(result: dict, filepath: str, report_dir: Path) -> Path:
    """Write HTML dashboard; returns the Path of the created file."""
    folder = report_dir / "html"
    folder.mkdir(parents=True, exist_ok=True)
    out = get_next_filename(folder, "visual_report", "html")

    risk       = _risk_score(result["gaps"], result["threats"])
    risk_color = "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 40 else "#10b981")
    sys_info   = get_system_metadata()
    perf       = result["performance"]
    stats      = result["stats"]
    eb         = result["entropy_baseline"]

    def tag_html(label: str, color: str = "blue") -> str:
        return f'<span class="tag tag-{color}">{html.escape(label)}</span>'

    def gen_threat_rows(subset: list) -> str:
        if not subset:
            return '<tr><td colspan="5" class="no-data">No threats detected in this zone.</td></tr>'
        rows = []
        for t in subset:
            kc_badge  = f'<span class="kc-badge">KC:{t["kill_chain_score"]}</span>' if t["kill_chain_score"] >= 2 else ""
            ioc_badge = tag_html("IOC", "red") if t.get("is_ioc") else ""
            tag_html_str = " ".join(
                tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED", "KNOWN_MALICIOUS_IOC",
                                             "LOG_TAMPERING", "DATA_EXFIL") else "blue")
                for tg in t["risk_tags"]
            )
            rows.append(
                f"<tr><td><strong>{html.escape(t['ip'])}</strong>{ioc_badge}</td>"
                f"<td>{t['hits']}</td>"
                f"<td>{t['session_count']}</td>"
                f"<td>{kc_badge}</td>"
                f"<td>{tag_html_str}</td></tr>"
            )
        return "".join(rows)

    priv_esc    = [t for t in result["threats"] if "PRIV_ESCALATION"     in t["risk_tags"]]
    brute_force = [t for t in result["threats"] if "BRUTE_FORCE_BURST"   in t["risk_tags"]
                                                or "FAILED_LOGIN"         in t["risk_tags"]]
    distributed = [t for t in result["threats"] if "DISTRIBUTED_ATTACK"  in t["risk_tags"]]
    log_tamper  = [t for t in result["threats"] if "LOG_TAMPERING"        in t["risk_tags"]]
    exfil       = [t for t in result["threats"] if "DATA_EXFIL"           in t["risk_tags"]]
    lateral     = [t for t in result["threats"] if "LATERAL_MOVEMENT"     in t["risk_tags"]]
    kill_chain  = [t for t in result["threats"] if "KILL_CHAIN_DETECTED"  in t["risk_tags"]]
    entropy_hits= [t for t in result["threats"] if "HIGH_ENTROPY_PAYLOAD" in t["risk_tags"]]
    ioc_hits    = [t for t in result["threats"] if t.get("is_ioc")]

    def gap_rows(gap_type: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gap_type]
        if not subset:
            return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(
            f"<tr><td>{tag_html(g['severity'], 'red')}</td>"
            f"<td>{html.escape(g.get('duration_human', 'N/A'))}</td>"
            f"<td>{g['start_line']}–{g['end_line']}</td>"
            f"<td>{html.escape(g['gap_start'][:19])}</td></tr>"
            for g in subset
        )

    max_hits = max((t["hits"] for t in result["threats"]), default=1)

    actor_bars = ""
    for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10]:
        pct = int(t["hits"] / max_hits * 100)
        col = "#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else (
              "#f59e0b" if t["kill_chain_score"] >= 2 else "#3b82f6")
        actor_bars += (
            f'<div class="actor-row">'
            f'<span class="actor-ip">{html.escape(t["ip"])}</span>'
            f'<div class="actor-bar-wrap"><div class="actor-bar" style="width:{pct}%;background:{col}"></div></div>'
            f'<span class="actor-hits">{t["hits"]}</span>'
            f'</div>'
        )

    compare_section = ""
    if result.get("compare") and result["compare"]["count"]:
        new_ip_list = ", ".join(result["compare"]["new_actors"][:20])
        compare_section = f"""
        <div class="card">
            <h3>🔄 Comparative Analysis – New Actors</h3>
            <p style="color:var(--secondary);font-size:13px;">
                {result['compare']['count']} IPs found in comparison file not present in baseline log.
            </p>
            <p style="font-family:monospace;font-size:12px;word-break:break-all;">{html.escape(new_ip_list)}</p>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Evidence Protector v6.0 – {html.escape(os.path.basename(filepath))}</title>
<style>
:root {{
  --primary:#111827; --secondary:#6b7280; --danger:#ef4444;
  --warning:#f59e0b; --success:#10b981; --info:#3b82f6;
  --bg:#f3f4f6; --card-bg:#ffffff; --border:#e5e7eb;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--primary);padding:24px;line-height:1.6;font-size:14px}}
.container{{max-width:1280px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;letter-spacing:-0.5px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px}}
h3{{font-size:15px;font-weight:700;margin-bottom:12px}}
.card{{background:var(--card-bg);border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);padding:24px;margin-bottom:20px;border:1px solid var(--border)}}
.grid-2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:20px}}
.grid-4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:20px}}
.stat-pill{{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.stat-pill .val{{font-size:28px;font-weight:900;line-height:1}}
.stat-pill .lbl{{font-size:11px;color:var(--secondary);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
.risk-meter{{height:48px;background:#e5e7eb;border-radius:24px;overflow:hidden;margin:12px 0;position:relative;border:1px solid var(--border)}}
.risk-fill{{height:100%;background:{risk_color};transition:width .5s ease;width:{risk}%}}
.risk-text{{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:17px;text-shadow:0 1px 4px rgba(0,0,0,.5)}}
details{{border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fafafa;overflow:hidden}}
summary{{padding:14px 18px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;border-left:4px solid var(--secondary)}}
summary::-webkit-details-marker{{display:none}}
summary::after{{content:'▼';margin-left:auto;font-size:11px;transition:transform .2s;color:var(--secondary)}}
details[open] summary::after{{transform:rotate(180deg)}}
details[open] summary{{border-left-color:var(--primary);background:#fff;border-bottom:1px solid var(--border)}}
.inner{{border:none;background:transparent;margin:8px 0;border-radius:0}}
.inner summary{{padding:10px 18px;font-size:13px;background:#f1f5f9;border-left:3px solid var(--secondary);font-weight:600}}
.table-wrap{{padding:12px 16px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f8fafc;color:var(--secondary);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
tr:last-child td{{border:none}}
tr:hover td{{background:#f9fafb}}
.tag{{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px;display:inline-block}}
.tag-red{{background:#fee2e2;color:#991b1b}}
.tag-blue{{background:#dbeafe;color:#1e40af}}
.tag-green{{background:#d1fae5;color:#065f46}}
.tag-yellow{{background:#fef3c7;color:#92400e}}
.kc-badge{{background:#7c3aed;color:#fff;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;margin-left:6px}}
.no-data{{color:var(--secondary);font-style:italic;text-align:center;padding:16px}}
.story-card{{background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px;margin-bottom:20px;border-left:5px solid #38bdf8}}
.story-card p{{line-height:1.8;font-size:14px}}
.meta-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13px}}
.meta-row:last-child{{border:none}}
.meta-label{{color:var(--secondary)}}
.meta-val{{font-weight:600}}
.actor-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}}
.actor-ip{{width:130px;font-family:monospace;font-size:12px;flex-shrink:0;color:var(--primary)}}
.actor-bar-wrap{{flex:1;height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden}}
.actor-bar{{height:100%;border-radius:5px;transition:width .4s ease}}
.actor-hits{{width:50px;text-align:right;color:var(--secondary);font-size:12px}}
.entropy-info{{font-size:12px;color:var(--secondary);padding:10px 16px;background:#f8fafc;border-bottom:1px solid var(--border)}}
footer{{text-align:center;color:var(--secondary);font-size:11px;padding:20px 0}}
.zone-header{{display:flex;align-items:center;gap:8px}}
.zone-count{{background:var(--danger);color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700}}
.zone-count.ok{{background:var(--success)}}
</style>
</head><body><div class="container">

<div class="card">
  <h1>🛡️ Evidence Protector v6.0</h1>
  <p style="color:var(--secondary);margin:4px 0 16px;">Forensic Audit: <strong>{html.escape(os.path.basename(filepath))}</strong> &nbsp;·&nbsp; {sys_info['ts'][:19]}</p>
  <div class="risk-meter">
    <div class="risk-fill"></div>
    <div class="risk-text">SYSTEM COMPROMISE PROBABILITY: {risk}%</div>
  </div>
</div>

<div class="grid-4">
  <div class="stat-pill"><div class="val" style="color:{'#ef4444' if result['gaps'] else '#10b981'}">{len(result['gaps'])}</div><div class="lbl">Timeline Anomalies</div></div>
  <div class="stat-pill"><div class="val" style="color:#f59e0b">{len(result['threats'])}</div><div class="lbl">Threat Actors</div></div>
  <div class="stat-pill"><div class="val" style="color:#7c3aed">{len(kill_chain)}</div><div class="lbl">Kill Chains</div></div>
  <div class="stat-pill"><div class="val" style="color:#ef4444">{len(ioc_hits)}</div><div class="lbl">IOC Matches</div></div>
  <div class="stat-pill"><div class="val" style="color:#3b82f6">{stats['obfuscated']}</div><div class="lbl">Entropy Alerts</div></div>
  <div class="stat-pill"><div class="val" style="color:#0891b2">{len(distributed)}</div><div class="lbl">Distributed Attackers</div></div>
  <div class="stat-pill"><div class="val">{stats['rare_templates']}</div><div class="lbl">Rare Templates</div></div>
  <div class="stat-pill"><div class="val" style="color:#10b981">{perf['lps']:,}</div><div class="lbl">Lines/sec</div></div>
</div>

<div class="grid-2">
  <div class="card">
    <h3>💻 System Metadata</h3>
    <div class="meta-row"><span class="meta-label">Hostname</span><span class="meta-val">{sys_info['host']}</span></div>
    <div class="meta-row"><span class="meta-label">OS</span><span class="meta-val">{sys_info['os']} {sys_info['ver']}</span></div>
    <div class="meta-row"><span class="meta-label">Architecture</span><span class="meta-val">{sys_info['arch']}</span></div>
    <div class="meta-row"><span class="meta-label">Processor</span><span class="meta-val">{sys_info['cpu'] or 'N/A'}</span></div>
  </div>
  <div class="card">
    <h3>📈 Analysis Intelligence</h3>
    <div class="meta-row"><span class="meta-label">Log Type</span><span class="meta-val">{stats['log_type']}</span></div>
    <div class="meta-row"><span class="meta-label">Throughput</span><span class="meta-val">{perf['lps']:,} lines/sec</span></div>
    <div class="meta-row"><span class="meta-label">Processing Time</span><span class="meta-val">{perf['time']}s</span></div>
    <div class="meta-row"><span class="meta-label">Entropy Baseline</span><span class="meta-val">μ={eb['mean']:.3f}  σ={eb['std']:.3f}  Θ={eb['threshold']:.3f}</span></div>
    <div class="meta-row"><span class="meta-label">Parsed / Total</span><span class="meta-val">{stats['parsed']:,} / {stats['total']:,}</span></div>
  </div>
</div>

<div class="story-card">
  <h3 style="margin-bottom:10px;">📖 Forensic Reconstruction</h3>
  <p>Analysis of <strong>{stats['total']:,}</strong> log lines identified <strong>{len(result['threats'])}</strong> active threat entities across
  <strong>{len(result['gaps'])}</strong> timeline integrity violations.
  {'<strong style="color:#f87171">Kill-chain sequences were confirmed for ' + str(len(kill_chain)) + ' actor(s)</strong>, indicating structured, multi-stage intrusion attempts.' if kill_chain else 'No confirmed kill-chain sequences were detected.'}
  {'<strong style="color:#fb923c">A distributed credential attack was identified involving ' + str(len(distributed)) + ' coordinated IPs.</strong>' if distributed else ''}
  The highest-activity source generated <strong>{max((t['hits'] for t in result['threats']), default=0):,}</strong> logged events.
  Entropy analysis (dynamic threshold: {eb['threshold']:.2f}) flagged <strong>{stats['obfuscated']}</strong> potentially obfuscated payloads.</p>
</div>

{'<div class="card"><h3>📊 Top Actor Activity</h3>' + actor_bars + '</div>' if actor_bars else ''}

{compare_section}

<div class="card">
  <h2>📂 Categorized Forensic Evidence</h2>

  <details>
    <summary>
      <div class="zone-header">⏱️ Zone 1: Timeline &amp; Integrity
        <span class="zone-count {'ok' if not result['gaps'] else ''}">{len(result['gaps'])}</span>
      </div>
    </summary>
    <div class="table-wrap">
      <details class="inner"><summary>Timeline Gaps (Potential Log Deletion)</summary>
        <table><thead><tr><th>Severity</th><th>Duration</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('GAP')}</tbody></table>
      </details>
      <details class="inner"><summary>Reversed Timestamps (Potential Tampering)</summary>
        <table><thead><tr><th>Severity</th><th>Delta</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('REVERSED')}</tbody></table>
      </details>
      <details class="inner"><summary>Anti-Forensic Commands (Log Tampering)</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(log_tamper)}</tbody></table>
      </details>
    </div>
  </details>

  <details>
    <summary>
      <div class="zone-header">🔐 Zone 2: Access &amp; Control
        <span class="zone-count {'ok' if not brute_force and not priv_esc else ''}">{len(brute_force)+len(priv_esc)}</span>
      </div>
    </summary>
    <div class="table-wrap">
      <details class="inner"><summary>Brute Force / Credential Attacks</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(brute_force)}</tbody></table>
      </details>
      <details class="inner"><summary>Distributed Attack Participants</summary>
        <div class="entropy-info">These IPs were part of a coordinated authentication storm detected across a {DISTRIBUTED_ATTACK_WINDOW}s window.</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(distributed)}</tbody></table>
      </details>
      <details class="inner"><summary>Privilege Escalation Attempts</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(priv_esc)}</tbody></table>
      </details>
      <details class="inner"><summary>Lateral Movement</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(lateral)}</tbody></table>
      </details>
    </div>
  </details>

  <details>
    <summary>
      <div class="zone-header">💀 Zone 3: Kill-Chain &amp; Confirmed Attacks
        <span class="zone-count {'ok' if not kill_chain else ''}">{len(kill_chain)}</span>
      </div>
    </summary>
    <div class="table-wrap">
      <details class="inner open"><summary>Kill-Chain Confirmed Actors</summary>
        <div class="entropy-info">Actors with ≥3 sequential kill-chain stages: {' → '.join(KILL_CHAIN_STAGES)}</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC Score</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(kill_chain)}</tbody></table>
      </details>
      <details class="inner"><summary>Data Exfiltration Indicators</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(exfil)}</tbody></table>
      </details>
    </div>
  </details>

  <details>
    <summary>
      <div class="zone-header">🔮 Zone 4: Obfuscation &amp; Entropy Analysis
        <span class="zone-count {'ok' if not entropy_hits else ''}">{len(entropy_hits)}</span>
      </div>
    </summary>
    <div class="table-wrap">
      <div class="entropy-info">
        Dynamic entropy threshold: <strong>{eb['threshold']:.3f}</strong> (baseline μ={eb['mean']:.3f}, σ={eb['std']:.3f}).
        Lines exceeding this threshold indicate packed, base64-encoded, or otherwise obfuscated payloads.
      </div>
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(entropy_hits) if entropy_hits else '<tr><td colspan="5" class="no-data">No obfuscated payloads detected.</td></tr>'}</tbody></table>
    </div>
  </details>

  <details>
    <summary>
      <div class="zone-header">🌐 Zone 5: IOC Feed Matches
        <span class="zone-count {'ok' if not ioc_hits else ''}">{len(ioc_hits)}</span>
      </div>
    </summary>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(ioc_hits) if ioc_hits else '<tr><td colspan="5" class="no-data">No IOC matches. Provide --ioc-feed to enable.</td></tr>'}</tbody></table>
    </div>
  </details>

</div>

<footer>Evidence Protector Engine v6.0 &nbsp;|&nbsp; {stats['parsed']:,} lines parsed &nbsp;|&nbsp; {stats['skipped']:,} noisy lines skipped &nbsp;|&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>

</div></body></html>"""

    with open(out, "w", encoding="utf-8") as f:
        f.write(html_content)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
# ── ENTRYPOINT ────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Evidence Protector v6.0 – Forensic Log Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s auth.log
  %(prog)s auth.log.gz --threshold 120
  %(prog)s access.log --ioc-feed known_bad_ips.txt
  %(prog)s auth.log --compare auth.log.1 --format html
  %(prog)s system.log --format terminal --threshold 60
        """
    )
    parser.add_argument("logfile",
                        help="Path to log file (.log, .gz, .bz2 supported)")
    parser.add_argument("--threshold", "-t",   type=float, default=300.0,
                        help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--ioc-feed",          type=str,   default=None,
                        help="Path to newline-delimited known-bad IP list")
    parser.add_argument("--compare",           type=str,   default=None,
                        help="Second log file for comparative actor profiling")
    parser.add_argument("--format", "-f",
                        choices=["all", "terminal", "json", "csv", "html"],
                        default="all",
                        help="Output format(s) (default: all)")
    args = parser.parse_args()

    # ── Resolve paths ────────────────────────────────────────────────────────
    log_path = Path(args.logfile).resolve()
    if not log_path.is_file():
        print(f"{C.RED}[!] File not found: {log_path}{C.RESET}")
        sys.exit(1)

    report_root = resolve_report_root()
    print(f"{C.DIM}[*] Reports root : {report_root}{C.RESET}")

    # ── IOC feed ─────────────────────────────────────────────────────────────
    ioc_set = load_ioc_feed(args.ioc_feed)
    if ioc_set:
        print(f"{C.CYAN}[*] IOC feed loaded: {len(ioc_set)} known-malicious IPs{C.RESET}")

    # ── Analysis ─────────────────────────────────────────────────────────────
    print(f"{C.DIM}[*] Scanning: {log_path} …{C.RESET}")
    result = scan_log(str(log_path), args.threshold,
                      ioc_set=ioc_set, compare_filepath=args.compare)

    # ── Output ───────────────────────────────────────────────────────────────
    fmt = args.format

    if fmt in ("all", "terminal"):
        report_terminal(result, str(log_path))

    if fmt in ("all", "csv"):
        f_integrity   = report_csv_integrity(result, report_root)
        f_behavioral  = report_csv_behavioral(result, report_root)
        print(f"📁 Integrity CSV  : {_file_uri(f_integrity)}")
        print(f"📁 Behavioral CSV : {_file_uri(f_behavioral)}")

    if fmt in ("all", "html"):
        f_html = report_html(result, str(log_path), report_root)
        print(f"🌐 Visual Report  : {_file_uri(f_html)}")

    if fmt in ("all", "json"):
        f_json = report_json(result, report_root)
        print(f"📄 JSON Data      : {_file_uri(f_json)}")


if __name__ == "__main__":
    main()
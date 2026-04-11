#!/usr/bin/env python3
"""
Log Detector and Foreign Threat Analysis
Damage-Matrix Assessment with Shannon Entropy, Kill-Chain Correlation,
Distributed Attack Detection, Session Reconstruction, and Dynamic Baselines.

Output files are saved to:
  ~/Documents/Forensic_Reports/
    csv/integrity_reportN.csv
    csv/threat_actorsN.csv
    html/visual_reportN.html
    json/forensic_dataN.json
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
from datetime import datetime, timedelta
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

# ── Project Identity ──────────────────────────────────────────────────────────
PROJECT_NAME    = "Log Detector and Foreign Threat Analysis"
PROJECT_VERSION = "1.0"
REPORT_ROOT_DIR = "Forensic_Reports"

# ── Pre-compiled Regex Patterns ───────────────────────────────────────────────
IP_PATTERN   = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

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
    "FAILED_LOGIN": re.compile(
        r"failed|invalid user|auth fail|password|denied|incorrect|"
        r"authentication failure|bad password|login failed", re.I),
    "PRIV_ESCALATION": re.compile(
        r"sudo|su -|privilege|elevated|root|uid=0|chmod 777|"
        r"visudo|pkexec|doas|newgrp", re.I),
    "SCANNING": re.compile(
        r"nmap|scan|probe|port|sqli|xss|select.*from|union.*select|"
        r"nikto|masscan|zmap|dirbuster|gobuster|ffuf|nuclei|"
        r"(?:GET|POST|HEAD)\s+/\S*\?.*=", re.I),
    "LOG_TAMPERING": re.compile(
        r"rm .*log|truncate|shred|history -c|clear-log|killall -9 syslogd|"
        r"echo.*>.*\.log|> /var/log|unlink.*log|wipe|auditctl -e 0", re.I),
    "SENSITIVE_ACCESS": re.compile(
        r"/etc/shadow|/etc/passwd|\.ssh/|id_rsa|config\.php|\.env|"
        r"/proc/self|/root/\.|lsass|SAM database|\.htpasswd|"
        r"wp-config\.php|database\.yml", re.I),
    "SERVICE_EVENTS": re.compile(
        r"restarted|shutdown|panic|segfault|crashed|oom-killer|"
        r"kernel: BUG|double free|use-after-free|stack smashing", re.I),
    "DATA_EXFIL": re.compile(
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
BRUTE_FORCE_THRESHOLD      = 5
BRUTE_FORCE_WINDOW_MIN     = 10
DISTRIBUTED_ATTACK_WINDOW  = 300    # 5-min bucket for distributed detection
DISTRIBUTED_FAIL_THRESHOLD = 15     # total fails across IPs in one window
SESSION_INACTIVITY_SEC     = 1800   # 30 min inactivity = new session
ENTROPY_BASELINE_LINES     = 500    # lines used to calibrate entropy baseline
ENTROPY_STD_MULTIPLIER     = 2.0    # stddev multiplier for dynamic threshold
ENTROPY_ABS_MIN            = 4.5    # never flag below this regardless of baseline
RARE_TEMPLATE_THRESHOLD    = 2      # log template seen ≤ this counts as "rare"
CURRENT_YEAR               = datetime.now().year


# ═══════════════════════════════════════════════════════════════════════════════
# ── OUTPUT PATH RESOLUTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_output_dir() -> Dict[str, str]:
    """
    Resolves and creates:
      ~/Documents/Forensic_Reports/{csv,html,json}/{YYYY-MM-DD}/
    """
    # 1. Get the current date for folder naming
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    if not os.path.isdir(documents):
        try:
            os.makedirs(documents, exist_ok=True)
        except OSError:
            documents = os.path.dirname(os.path.abspath(__file__))

    root_dir = os.path.join(documents, REPORT_ROOT_DIR)
    
    # 2. Add the date_str to the end of each path
    dirs = {
        "csv": os.path.join(root_dir, "csv", date_str),
        "html": os.path.join(root_dir, "html", date_str),
        "json": os.path.join(root_dir, "json", date_str),
    }
    
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
        
    return dirs

def make_output_paths(dirs: Dict[str, str]) -> Dict[str, str]:
    """
    Saves files as: {n}_{filename}_{timestamp}.ext
    Increments 'n' based on the highest existing 'n' in the folder.
    """
    # 1. Get current timestamp for the filename
    ts = datetime.now().strftime("%H%M%S")
    
    # 2. Find the highest existing 'n' in the directory
    existing_files = os.listdir(dirs["csv"])
    highest_n = 0
    
    for filename in existing_files:
        # Regex to find the leading number (e.g., "1" from "1_integrity...")
        match = re.match(r"^(\d+)_", filename)
        if match:
            n_val = int(match.group(1))
            if n_val > highest_n:
                highest_n = n_val
    
    # 3. New 'n' is the highest found + 1
    n = highest_n + 1

    # 4. Generate final paths
    return {
        "csv_integrity":  os.path.join(dirs["csv"],  f"{n}_integrity_report_{ts}.csv"),
        "csv_behavioral": os.path.join(dirs["csv"],  f"{n}_threat_actors_{ts}.csv"),
        "html":           os.path.join(dirs["html"], f"{n}_visual_report_{ts}.html"),
        "json":           os.path.join(dirs["json"], f"{n}_forensic_data_{ts}.json"),
    }
    """
    Saves files as: {n}_{filename}_{timestamp}.{ext}
    """
    # 1. Generate a high-resolution timestamp for the filename
    ts = datetime.now().strftime("%H%M%S") 
    
    n = 1
    while True:
        # 2. Updated filename format: n_name_timestamp.ext
        c1 = os.path.join(dirs["csv"], f"{n}_integrity_report_{ts}.csv")
        c2 = os.path.join(dirs["csv"], f"{n}_threat_actors_{ts}.csv")
        h  = os.path.join(dirs["html"], f"{n}_visual_report_{ts}.html")
        j  = os.path.join(dirs["json"], f"{n}_forensic_data_{ts}.json")
        
        # Check if this specific 'n' already exists for this second
        if not (os.path.exists(c1) or os.path.exists(c2) or os.path.exists(h) or os.path.exists(j)):
            break
        n += 1

    return {
        "csv_integrity":  c1,
        "csv_behavioral": c2,
        "html":           h,
        "json":           j,
    }
    """
    Generates unified serial-numbered output file paths.
    Finds the highest N in use and returns N+1.
    """
    n = 1
    while True:
        c1 = os.path.join(dirs["csv"], f"integrity_report{n}.csv")
        c2 = os.path.join(dirs["csv"], f"threat_actors{n}.csv")
        h  = os.path.join(dirs["html"], f"visual_report{n}.html")
        j  = os.path.join(dirs["json"], f"forensic_data{n}.json")
        
        if not (os.path.exists(c1) or os.path.exists(c2) or os.path.exists(h) or os.path.exists(j)):
            break
        n += 1

    return {
        "csv_integrity":  c1,
        "csv_behavioral": c2,
        "html":           h,
        "json":           j,
    }


def to_file_url(filepath: str) -> str:
    """Safely converts an absolute file path to a clickable file:// URI."""
    abs_path = os.path.abspath(filepath).replace("\\", "/")
    if not abs_path.startswith("/"):
        abs_path = "/" + abs_path
    return f"file://{abs_path}"


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
    """Return how many sequential kill-chain stages are present (0–5)."""
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


def _risk_zones(gaps: list, threats: list) -> Dict[str, float]:
    """
    Compute per-zone compromise probabilities driven entirely by observed evidence.

    Two core helpers replace every hardline constant:

    saturation(p_each, n)
        Independent-trials model: probability that at least one of `n` actors
        with individual success-probability `p_each` achieved their goal.
        Formula: 1 - (1 - p_each)^n
        Effect: 1 actor  → p_each (no inflation, no deflation)
                2 actors → natural compounding; always saturates smoothly.
        Why better: the old code gave the same score whether 1 or 50 IPs were
        brute-forcing. Now more actors always means more risk, but the curve
        flattens instead of hard-capping at an arbitrary number.

    hit_scaled_p(base, hits)
        Scales the per-actor base probability logarithmically with that actor's
        total recorded hits.  1 hit = base; 100 hits ≈ base × 1.3; 1000 hits ≈
        base × 1.5.  Capped at 0.97.
        Why better: an attacker who generated 3 000 log lines was far more
        active than one who generated 3.  That should raise confidence.

    Cross-cutting modifiers (IOC, kill-chain, entropy) use a *fractional boost
    to the remaining safe space* rather than a flat +0.10 addition:
        zone += (1 - zone) × multiplier
    A zone already at 0.95 barely moves; a zone at 0.20 gets a meaningful push.
    This prevents zones from trivially exceeding 0.99 via accumulation.
    """
    if not gaps and not threats:
        return {z: 0.0 for z in
                ("integrity","access","persistence","privacy",
                 "continuity","exfiltration","lateral")}

    # ── Core helpers ──────────────────────────────────────────────────────────

    def saturation(p_each: float, n: int) -> float:
        """P(at least one of n independent actors with prob p_each succeeds)."""
        if n <= 0:
            return 0.0
        return 1.0 - (1.0 - min(p_each, 0.97)) ** n

    def hit_scaled_p(base: float, hits: int) -> float:
        """Scale base probability upward by attacker activity volume (log scale)."""
        scale = 1.0 + 0.15 * math.log10(max(hits, 1))
        return min(base * scale, 0.97)

    def fractional_boost(current: float, multiplier: float) -> float:
        """Boost a probability toward 1.0 proportionally to remaining safe space."""
        return min(current + (1.0 - current) * multiplier, 0.99)

    # ── Build per-tag actor lists (one pass) ──────────────────────────────────
    tag_actors: Dict[str, list] = defaultdict(list)
    for t in threats:
        for tag in t["risk_tags"]:
            tag_actors[tag].append(t)

    def n(tag: str) -> int:
        return len(tag_actors[tag])

    def peak_hits(tag: str) -> int:
        return max((t["hits"] for t in tag_actors[tag]), default=1)

    # ── Zone 1: Integrity ─────────────────────────────────────────────────────
    # Reversed timestamps: strongest indicator of log tampering — each one is
    # an independent suspicious event.  Base probability per reversal: 0.70.
    reversed_gaps = [g for g in gaps if g["type"] == "REVERSED"]
    # Critical gaps (>1 h): possible log deletion.  Base per gap: 0.40.
    critical_gaps = [g for g in gaps if g["type"] == "GAP"
                     and g["severity"] == "CRITICAL"]
    # High gaps (threshold–1 h): suspicious but could be maintenance.  Base: 0.15.
    high_gaps     = [g for g in gaps if g["type"] == "GAP"
                     and g["severity"] == "HIGH"]

    p_rev  = saturation(0.70, len(reversed_gaps))
    p_crit = saturation(0.40, len(critical_gaps))
    p_high = saturation(0.15, len(high_gaps))

    # Additionally: the longer the largest gap, the more likely something was
    # deleted.  +5 % per hour, capped at +0.30.
    max_gap_sec = max(
        (g["duration_seconds"] for g in gaps if g["type"] == "GAP"), default=0
    )
    duration_factor = min(max_gap_sec / 3600 * 0.05, 0.30)

    # Combine all integrity signals as independent events.
    integrity = 1.0 - (
        (1.0 - p_rev) * (1.0 - p_crit) * (1.0 - p_high) * (1.0 - duration_factor)
    )

    # ── Zone 2: Access ────────────────────────────────────────────────────────
    # Privilege escalation: very high severity per actor.
    p_priv  = saturation(hit_scaled_p(0.60, peak_hits("PRIV_ESCALATION")),
                         n("PRIV_ESCALATION"))

    # Brute-force burst (confirmed rapid-fire attempt window).
    p_brute = saturation(hit_scaled_p(0.35, peak_hits("BRUTE_FORCE_BURST")),
                         n("BRUTE_FORCE_BURST"))

    # Plain failed logins (without a confirmed burst window) — lower base.
    # Only count actors who haven't already been counted under BRUTE_FORCE_BURST
    # to avoid double-weighting the same IP.
    n_failed_only = len([
        t for t in tag_actors["FAILED_LOGIN"]
        if "BRUTE_FORCE_BURST" not in t["risk_tags"]
    ])
    p_failed = saturation(hit_scaled_p(0.10, peak_hits("FAILED_LOGIN")),
                          n_failed_only)

    # Distributed attack: each participating IP independently raises the bar.
    p_dist  = saturation(0.25, n("DISTRIBUTED_ATTACK"))

    access = 1.0 - (
        (1.0 - p_priv) * (1.0 - p_brute) * (1.0 - p_failed) * (1.0 - p_dist)
    )

    # ── Zone 3: Persistence (log tampering) ───────────────────────────────────
    # Even one actor attempting log tampering is very serious; more actors or
    # higher hit counts increase confidence further.
    persistence = saturation(hit_scaled_p(0.80, peak_hits("LOG_TAMPERING")),
                             n("LOG_TAMPERING"))

    # ── Zone 4: Privacy (sensitive file access) ───────────────────────────────
    privacy = saturation(hit_scaled_p(0.50, peak_hits("SENSITIVE_ACCESS")),
                         n("SENSITIVE_ACCESS"))

    # ── Zone 5: Continuity (service disruption events) ────────────────────────
    continuity = saturation(hit_scaled_p(0.30, peak_hits("SERVICE_EVENTS")),
                            n("SERVICE_EVENTS"))

    # ── Zone 6: Exfiltration ──────────────────────────────────────────────────
    exfiltration = saturation(hit_scaled_p(0.65, peak_hits("DATA_EXFIL")),
                              n("DATA_EXFIL"))

    # ── Zone 7: Lateral movement ──────────────────────────────────────────────
    lateral = saturation(hit_scaled_p(0.55, peak_hits("LATERAL_MOVEMENT")),
                         n("LATERAL_MOVEMENT"))

    zone_probs: Dict[str, float] = {
        "integrity":    integrity,
        "access":       access,
        "persistence":  persistence,
        "privacy":      privacy,
        "continuity":   continuity,
        "exfiltration": exfiltration,
        "lateral":      lateral,
    }

    # ── Cross-cutting modifier 1: IOC-confirmed actors ────────────────────────
    # Each known-bad IP is independent confirmation that real attackers are
    # present; boost all active zones proportional to IOC actor count.
    # Cap at +50 % of remaining safe space so it never dominates alone.
    n_ioc = len([t for t in threats if t.get("is_ioc")])
    if n_ioc > 0:
        ioc_multiplier = min(n_ioc * 0.15, 0.50)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], ioc_multiplier)

    # ── Cross-cutting modifier 2: kill-chain stage depth ─────────────────────
    # Higher stage count = attacker has progressed further through intrusion
    # lifecycle.  The boost scales linearly with the deepest observed score
    # (0–5), up to +35 % of remaining safe space.
    if n("KILL_CHAIN_DETECTED") > 0:
        max_kc = max(
            (t["kill_chain_score"] for t in tag_actors["KILL_CHAIN_DETECTED"]),
            default=0,
        )
        kc_multiplier = min((max_kc / len(KILL_CHAIN_STAGES)) * 0.35, 0.35)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], kc_multiplier)

    # ── Cross-cutting modifier 3: high-entropy / obfuscated payloads ──────────
    # Obfuscation indicates a sophisticated attacker trying to evade detection;
    # a small general confidence boost across all active zones.
    # Cap at +15 % of remaining safe space.
    n_entropy = n("HIGH_ENTROPY_PAYLOAD")
    if n_entropy > 0:
        entropy_multiplier = min(n_entropy * 0.02, 0.15)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], entropy_multiplier)

    return zone_probs


def _risk_score(gaps: list, threats: list) -> int:
    """
    Collapse zone probabilities into a single 0–99 headline risk score.

    Uses the independent-zone saturation formula:
        P(compromise) = 1 - ∏(1 - P(zone_i))
    so each zone that is non-zero contributes independently.
    Signature is unchanged from the original, so all callers are unaffected.
    """
    zone_probs = _risk_zones(gaps, threats)
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
             ioc_set: Set[str] = None, compare_filepath: str = None) -> Dict:
    """
    Main analysis pass. Single O(N) scan with post-pass enrichment.
    Returns a structured result dict consumed by all report functions.
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
    entropy_threshold = max(ENTROPY_ABS_MIN,
                            entropy_mean + ENTROPY_STD_MULTIPLIER * entropy_std)

    # ── Phase 1: Main Analysis Pass ──────────────────────────────────────────
    gaps             = []
    total_lines      = 0
    parsed_lines     = 0
    skipped_lines    = 0
    prev_ts          = None
    first_ts         = None
    last_ts          = None
    ip_stats: Dict   = {}
    template_counts  = Counter()
    obfuscated_count = 0
    log_type         = None
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

                # Integrity check
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

                # Rare template detection
                tmpl = log_template(line_content)
                template_counts[tmpl] += 1

                # Entity profiling
                ip_match = IP_PATTERN.search(line_content)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ip_stats:
                        ip_stats[ip] = {
                            "first":   ts,
                            "last":    ts,
                            "hits":    0,
                            "fails":   deque(maxlen=50),
                            "events":  [],
                            "tags":    set(),
                        }
                    stats = ip_stats[ip]
                    stats["hits"] += 1
                    stats["last"]  = ts
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
    rare_templates = {t for t, c in template_counts.items()
                      if c <= RARE_TEMPLATE_THRESHOLD}

    distributed_attack_ips: Set[str] = set()
    for bucket, events in time_buckets.items():
        fail_events    = [(ip, f) for ip, f in events if f]
        unique_fail_ips = set(ip for ip, _ in fail_events)
        if (len(fail_events) >= DISTRIBUTED_FAIL_THRESHOLD
                and len(unique_fail_ips) >= 3):
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
                "ip":               ip,
                "risk_tags":        sorted(list(s["tags"])),
                "hits":             s["hits"],
                "span":             str(s["last"] - s["first"]),
                "sessions":         sessions,
                "session_count":    len(sessions),
                "kill_chain_score": kc_score,
                "is_ioc":           ip in ioc_set,
            })

    compare_result = None
    if compare_filepath and os.path.isfile(compare_filepath):
        compare_result = _compare_profile(compare_filepath, ip_stats)

    proc_time = time.time() - start_time

    # Compute zone breakdown once here so every report function can read it
    # from result["risk_breakdown"] without re-running the calculation.
    risk_breakdown = _risk_zones(gaps, final_threats)

    return {
        "gaps":    gaps,
        "threats": final_threats,
        "risk_breakdown": {z: round(p, 4) for z, p in risk_breakdown.items()},
        "performance": {
            "time": round(proc_time, 3),
            "lps":  int(total_lines / proc_time) if proc_time > 0 else 0,
        },
        "stats": {
            "total":               total_lines,
            "parsed":              parsed_lines,
            "skipped":             skipped_lines,
            "obfuscated":          obfuscated_count,
            "log_type":            log_type or "Mixed/Unknown",
            "rare_templates":      len(rare_templates),
            "distributed_windows": len([
                b for b in time_buckets.values()
                if len([e for e in b if e[1]]) >= DISTRIBUTED_FAIL_THRESHOLD
            ]),
        },
        "entropy_baseline": {
            "mean":      round(entropy_mean, 3),
            "std":       round(entropy_std, 3),
            "threshold": round(entropy_threshold, 3),
        },
        "compare": compare_result,
    }


def _compare_profile(filepath2: str, baseline_ip_stats: Dict) -> Dict:
    """Compare second log file — report IPs absent from baseline (new actors)."""
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
    """Helper for terminal progress bars."""
    filled = int(round(value / max_val * width)) if max_val else 0
    return char * filled + C.DIM + "░" * (width - filled) + C.RESET


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
    print(f"{C.CYAN}  _     ___   ____   ____   _____   _____   _____   ____   _____   ___   ____  ")
    print(f" | |   / _ \\ / ___| |  _ \\ | ____| |_   _| | ____| / ___| |_   _| / _ \\ |  _ \\ ")
    print(f" | |  | | | | |  _  | | | | |  _|     | |   |  _|  | |       | |  | | | || |_) |")
    print(f" | |__| |_| | |_| | | |_| | | |___    | |   | |__  | |___    | |  | |_| ||  _ < ")
    print(f" |_____\\___/ \\____| |____/  |_____|   |_|   |_____| \\____|   |_|   \\___/ |_| \\_\\{C.RESET}")
    print(f"")
    print(f" {C.BOLD}Foreign Threat Analysis | v{PROJECT_VERSION}{C.RESET}")
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

    # Per-zone breakdown — only show zones with non-zero probability so the
    # display stays clean on benign logs.
    zone_labels = {
        "integrity":    "Integrity   ",
        "access":       "Access      ",
        "persistence":  "Persistence ",
        "privacy":      "Privacy     ",
        "continuity":   "Continuity  ",
        "exfiltration": "Exfiltration",
        "lateral":      "Lateral Mvmt",
    }
    breakdown = result.get("risk_breakdown", {})
    active_zones = [(z, p) for z, p in breakdown.items() if p > 0.0]
    if active_zones:
        print(f"\n {C.BOLD}[RISK ZONES]{C.RESET}")
        for z, p in active_zones:
            pct = int(p * 100)
            z_col = C.RED if pct >= 75 else (C.YELLOW if pct >= 40 else C.GREEN)
            print(f"  {zone_labels.get(z, z)}  {z_col}{pct:>3}%{C.RESET}  "
                  f"{z_col}{_bar(pct, 100, width=30)}{C.RESET}")

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
        print(f"  New Actors (compare): {C.YELLOW}{result['compare']['count']:>3} previously unseen IPs{C.RESET}")

    if result["threats"]:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        print(f"  {'ENTITY (IP)':<17}| {'HITS':<7}| {'KC':<4}| {'SESS':<5}| RISK INDICATORS")
        print(f"  {'-'*17}+-{'-'*7}+-{'-'*4}+-{'-'*5}+-{'-'*38}")
        sorted_threats = sorted(result["threats"],
                                key=lambda x: (x["kill_chain_score"], x["hits"]),
                                reverse=True)
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
                  f"{g.get('duration_human','N/A'):<20} {g['start_line']}-{g['end_line']}")

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ── FILE OUTPUT FUNCTIONS ─────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def report_csv_integrity(result: dict, path: str):
    fields = ["type", "gap_start", "gap_end", "duration_human",
              "duration_seconds", "severity", "start_line", "end_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for g in result["gaps"]:
            writer.writerow({k: g.get(k, "N/A") for k in fields})


def report_csv_behavioral(result: dict, path: str):
    fields = ["ip", "hits", "span", "kill_chain_score",
              "session_count", "is_ioc", "risk_tags"]
    with open(path, "w", newline="", encoding="utf-8") as f:
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


def report_json(result: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)


def _build_zone_breakdown_html(breakdown: dict, tag_html_fn) -> str:
    """
    Render the per-zone risk bars for the HTML report.
    Each zone bar is coloured green / amber / red based on its probability,
    and a short plain-English driver note explains what raised it.
    This function is called once inside report_html; it reads from
    result["risk_breakdown"] which scan_log pre-computes via _risk_zones().
    """
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
        col = "#ef4444" if pct >= 75 else ("#f59e0b" if pct >= 40 else
              "#10b981" if pct > 0 else "#d1d5db")
        txt_col = col
        rows.append(f"""
  <div class="zone-breakdown-row">
    <span class="zone-breakdown-label">{label}</span>
    <div class="zone-breakdown-bar-wrap">
      <div class="zone-breakdown-bar" style="width:{pct}%;background:{col}"></div>
    </div>
    <span class="zone-breakdown-pct" style="color:{txt_col}">{pct}%</span>
  </div>
  <div class="zone-breakdown-note">{note}</div>""")
    return "\n".join(rows)


def report_html(result: dict, filepath: str, path: str):
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
            tag_str   = " ".join(
                tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED", "KNOWN_MALICIOUS_IOC",
                                             "LOG_TAMPERING", "DATA_EXFIL") else "blue")
                for tg in t["risk_tags"]
            )
            rows.append(
                f"<tr>"
                f"<td><strong>{html.escape(t['ip'])}</strong>{ioc_badge}</td>"
                f"<td>{t['hits']}</td>"
                f"<td>{t['session_count']}</td>"
                f"<td>{kc_badge}</td>"
                f"<td>{tag_str}</td>"
                f"</tr>"
            )
        return "".join(rows)

    def gap_rows(gap_type: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gap_type]
        if not subset:
            return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(
            f"<tr><td>{tag_html(g['severity'], 'red')}</td>"
            f"<td>{html.escape(g.get('duration_human','N/A'))}</td>"
            f"<td>{g['start_line']}–{g['end_line']}</td>"
            f"<td>{html.escape(g['gap_start'][:19])}</td></tr>"
            for g in subset
        )

    # Threat category subsets
    priv_esc    = [t for t in result["threats"] if "PRIV_ESCALATION"    in t["risk_tags"]]
    brute_force = [t for t in result["threats"] if "BRUTE_FORCE_BURST"  in t["risk_tags"]
                                                or "FAILED_LOGIN"       in t["risk_tags"]]
    distributed = [t for t in result["threats"] if "DISTRIBUTED_ATTACK" in t["risk_tags"]]
    log_tamper  = [t for t in result["threats"] if "LOG_TAMPERING"      in t["risk_tags"]]
    exfil       = [t for t in result["threats"] if "DATA_EXFIL"         in t["risk_tags"]]
    lateral     = [t for t in result["threats"] if "LATERAL_MOVEMENT"   in t["risk_tags"]]
    kill_chain  = [t for t in result["threats"] if "KILL_CHAIN_DETECTED" in t["risk_tags"]]
    entropy_hits= [t for t in result["threats"] if "HIGH_ENTROPY_PAYLOAD" in t["risk_tags"]]
    ioc_hits    = [t for t in result["threats"] if t.get("is_ioc")]

    max_hits = max((t["hits"] for t in result["threats"]), default=1)
    actor_bars = ""
    for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10]:
        pct = int(t["hits"] / max_hits * 100)
        col = ("#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else
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
                {result['compare']['count']} IPs found in comparison file not present in baseline.
            </p>
            <p style="font-family:monospace;font-size:12px;word-break:break-all;">{html.escape(new_ip_list)}</p>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{html.escape(PROJECT_NAME)} – {html.escape(os.path.basename(filepath))}</title>
<style>
:root {{
  --primary:#111827; --secondary:#6b7280; --danger:#ef4444;
  --warning:#f59e0b; --success:#10b981; --info:#3b82f6;
  --bg:#f3f4f6; --card-bg:#ffffff; --border:#e5e7eb;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--primary);padding:24px;line-height:1.6;font-size:14px}}
.container{{max-width:1280px;margin:0 auto}}
h1{{font-size:24px;font-weight:800;letter-spacing:-.5px}}
h2{{font-size:18px;font-weight:700;margin-bottom:16px}}
h3{{font-size:15px;font-weight:700;margin-bottom:12px}}
.card{{background:var(--card-bg);border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.08);padding:24px;margin-bottom:20px;border:1px solid var(--border)}}
.grid-2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;margin-bottom:20px}}
.grid-4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:20px}}
.stat-pill{{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}}
.stat-pill .val{{font-size:28px;font-weight:900;line-height:1}}
.stat-pill .lbl{{font-size:11px;color:var(--secondary);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
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
.table-wrap{{padding:12px 16px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#f8fafc;color:var(--secondary);text-transform:uppercase;font-size:10px;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid var(--border)}}
td{{padding:10px 12px;border-bottom:1px solid #f1f5f9}}
tr:last-child td{{border:none}}
tr:hover td{{background:#f9fafb}}
.tag{{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;margin:2px;display:inline-block}}
.tag-red{{background:#fee2e2;color:#991b1b}}
.tag-blue{{background:#dbeafe;color:#1e40af}}
.kc-badge{{background:#7c3aed;color:#fff;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;margin-left:6px}}
.no-data{{color:var(--secondary);font-style:italic;text-align:center;padding:16px}}
.story-card{{background:#0f172a;color:#e2e8f0;padding:24px;border-radius:12px;margin-bottom:20px;border-left:5px solid #38bdf8}}
.story-card p{{line-height:1.8;font-size:14px}}
.meta-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px dashed var(--border);font-size:13px}}
.meta-row:last-child{{border:none}}
.meta-label{{color:var(--secondary)}}
.meta-val{{font-weight:600}}
.actor-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px;font-size:13px}}
.actor-ip{{width:130px;font-family:monospace;font-size:12px;flex-shrink:0}}
.actor-bar-wrap{{flex:1;height:10px;background:#e5e7eb;border-radius:5px;overflow:hidden}}
.actor-bar{{height:100%;border-radius:5px}}
.actor-hits{{width:50px;text-align:right;color:var(--secondary);font-size:12px}}
.entropy-info{{font-size:12px;color:var(--secondary);padding:10px 16px;background:#f8fafc;border-bottom:1px solid var(--border)}}
.zone-header{{display:flex;align-items:center;gap:8px}}
.zone-count{{background:var(--danger);color:#fff;border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700}}
.zone-count.ok{{background:var(--success)}}
.file-path{{font-family:monospace;font-size:11px;background:#f1f5f9;padding:3px 8px;border-radius:4px;color:#374151}}
footer{{text-align:center;color:var(--secondary);font-size:11px;padding:20px 0}}
.zone-breakdown-row{{display:flex;align-items:center;gap:12px;margin-bottom:10px;font-size:13px}}
.zone-breakdown-label{{width:110px;font-weight:600;color:var(--primary);flex-shrink:0;font-size:12px}}
.zone-breakdown-bar-wrap{{flex:1;height:14px;background:#e5e7eb;border-radius:7px;overflow:hidden}}
.zone-breakdown-bar{{height:100%;border-radius:7px;transition:width .4s ease}}
.zone-breakdown-pct{{width:40px;text-align:right;font-weight:700;font-size:12px}}
.zone-breakdown-note{{font-size:11px;color:var(--secondary);margin-top:2px;padding-left:122px}}
</style>
</head><body><div class="container">

<div class="card">
  <h1>🔍 {html.escape(PROJECT_NAME)}</h1>
  <p style="color:var(--secondary);margin:4px 0 4px;">
    Forensic Audit: <strong>{html.escape(os.path.basename(filepath))}</strong>
    &nbsp;·&nbsp; {sys_info['ts'][:19]}
  </p>
  <p style="margin-bottom:16px;font-size:12px;color:var(--secondary);">
    Report saved to: <span class="file-path">{html.escape(path)}</span>
  </p>
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
  {'<strong style="color:#f87171">Kill-chain sequences confirmed for ' + str(len(kill_chain)) + ' actor(s)</strong>, indicating structured multi-stage intrusion.' if kill_chain else 'No confirmed kill-chain sequences detected.'}
  {'<strong style="color:#fb923c"> Distributed credential attack involving ' + str(len(distributed)) + ' coordinated IPs.</strong>' if distributed else ''}
  Peak activity: <strong>{max((t['hits'] for t in result['threats']), default=0):,}</strong> events from a single source.
  Entropy analysis (Θ={eb['threshold']:.2f}) flagged <strong>{stats['obfuscated']}</strong> obfuscated payloads.</p>
</div>

{'<div class="card"><h3>📊 Top Actor Activity</h3>' + actor_bars + '</div>' if actor_bars else ''}

{compare_section}

<div class="card">
  <h3>🎯 Risk Zone Breakdown</h3>
  <p style="color:var(--secondary);font-size:12px;margin-bottom:16px;">
    Each zone's probability is computed from the number of actors exhibiting
    that behaviour, their activity volume, and cross-cutting signals
    (IOC matches, kill-chain depth, entropy). Values compound into the headline score above.
  </p>
{_build_zone_breakdown_html(result.get("risk_breakdown", {}), tag_html)}
</div>

<div class="card">
  <h2>📂 Categorized Forensic Evidence</h2>

  <details>
    <summary><div class="zone-header">⏱️ Zone 1: Timeline &amp; Integrity
      <span class="zone-count {'ok' if not result['gaps'] else ''}">{len(result['gaps'])}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Timeline Gaps (Potential Log Deletion)</summary>
        <table><thead><tr><th>Severity</th><th>Duration</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('GAP')}</tbody></table></details>
      <details class="inner"><summary>Reversed Timestamps (Potential Tampering)</summary>
        <table><thead><tr><th>Severity</th><th>Delta</th><th>Lines</th><th>Started</th></tr></thead>
        <tbody>{gap_rows('REVERSED')}</tbody></table></details>
      <details class="inner"><summary>Anti-Forensic Commands</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(log_tamper)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🔐 Zone 2: Access &amp; Control
      <span class="zone-count {'ok' if not brute_force and not priv_esc else ''}">{len(brute_force)+len(priv_esc)}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Brute Force / Credential Attacks</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(brute_force)}</tbody></table></details>
      <details class="inner"><summary>Distributed Attack Participants</summary>
        <div class="entropy-info">Coordinated authentication storm across a {DISTRIBUTED_ATTACK_WINDOW}s window.</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(distributed)}</tbody></table></details>
      <details class="inner"><summary>Privilege Escalation Attempts</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(priv_esc)}</tbody></table></details>
      <details class="inner"><summary>Lateral Movement</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(lateral)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">💀 Zone 3: Kill-Chain &amp; Confirmed Attacks
      <span class="zone-count {'ok' if not kill_chain else ''}">{len(kill_chain)}</span></div></summary>
    <div class="table-wrap">
      <details class="inner"><summary>Kill-Chain Confirmed Actors</summary>
        <div class="entropy-info">Stages: {' → '.join(KILL_CHAIN_STAGES)}</div>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC Score</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(kill_chain)}</tbody></table></details>
      <details class="inner"><summary>Data Exfiltration Indicators</summary>
        <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
        <tbody>{gen_threat_rows(exfil)}</tbody></table></details>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🔮 Zone 4: Obfuscation &amp; Entropy
      <span class="zone-count {'ok' if not entropy_hits else ''}">{len(entropy_hits)}</span></div></summary>
    <div class="table-wrap">
      <div class="entropy-info">Dynamic threshold: <strong>{eb['threshold']:.3f}</strong> (μ={eb['mean']:.3f}, σ={eb['std']:.3f}). Lines above threshold indicate packed/encoded payloads.</div>
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(entropy_hits) if entropy_hits else '<tr><td colspan="5" class="no-data">No obfuscated payloads detected.</td></tr>'}</tbody></table>
    </div>
  </details>

  <details>
    <summary><div class="zone-header">🌐 Zone 5: IOC Feed Matches
      <span class="zone-count {'ok' if not ioc_hits else ''}">{len(ioc_hits)}</span></div></summary>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Hits</th><th>Sessions</th><th>KC</th><th>Tags</th></tr></thead>
      <tbody>{gen_threat_rows(ioc_hits) if ioc_hits else '<tr><td colspan="5" class="no-data">No IOC matches. Use --ioc-feed to enable.</td></tr>'}</tbody></table>
    </div>
  </details>

</div>

<footer>
  {html.escape(PROJECT_NAME)} v{PROJECT_VERSION}
  &nbsp;|&nbsp; {stats['parsed']:,} lines parsed
  &nbsp;|&nbsp; {stats['skipped']:,} noisy lines skipped
  &nbsp;|&nbsp; Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</footer>

</div></body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)


# ═══════════════════════════════════════════════════════════════════════════════
# ── ENTRYPOINT ────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f"{PROJECT_NAME} v{PROJECT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Output location (auto-created):
  ~/Documents/{REPORT_ROOT_DIR}/
    csv/integrity_reportN.csv
    csv/threat_actorsN.csv
    html/visual_reportN.html
    json/forensic_dataN.json

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
    parser.add_argument("--threshold", "-t", type=float, default=300.0,
                        help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--ioc-feed",        type=str,   default=None,
                        help="Path to newline-delimited known-bad IP list")
    parser.add_argument("--compare",         type=str,   default=None,
                        help="Second log file for comparative actor profiling")
    parser.add_argument("--format", "-f",
                        choices=["all", "terminal", "json", "csv", "html"],
                        default="all",
                        help="Output format(s) (default: all)")
    args = parser.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"{C.RED}[!] File not found: {args.logfile}{C.RESET}")
        sys.exit(1)

    # ── Resolve output directory and file paths ───────────────────────────────
    out_dirs  = resolve_output_dir()
    out_paths = make_output_paths(out_dirs)

    print(f"\n{C.CYAN}[*] {PROJECT_NAME} v{PROJECT_VERSION}{C.RESET}")
    print(f"{C.DIM}[*] Scanning      : {args.logfile} …{C.RESET}\n")

    ioc_set = load_ioc_feed(args.ioc_feed)
    if ioc_set:
        print(f"{C.CYAN}[*] IOC feed loaded: {len(ioc_set)} known-malicious IPs{C.RESET}")

    result = scan_log(args.logfile, args.threshold,
                      ioc_set=ioc_set, compare_filepath=args.compare)

    fmt = args.format

    if fmt in ("all", "terminal"):
        report_terminal(result, args.logfile)

    if fmt in ("all", "csv"):
        report_csv_integrity(result,  out_paths["csv_integrity"])
        report_csv_behavioral(result, out_paths["csv_behavioral"])
    if fmt in ("all", "html"):
        report_html(result, args.logfile, out_paths["html"])
    if fmt in ("all", "json"):
        report_json(result, out_paths["json"])

    if fmt != "terminal":
        print(f"📁 {C.BOLD}Integrity CSV{C.RESET}  : {to_file_url(out_paths['csv_integrity'])}")
        print(f"📁 {C.BOLD}Behavioral CSV{C.RESET} : {to_file_url(out_paths['csv_behavioral'])}")
        print(f"🌐 {C.BOLD}Visual Report{C.RESET}  : {to_file_url(out_paths['html'])}")
        print(f"📄 {C.BOLD}JSON Data{C.RESET}      : {to_file_url(out_paths['json'])}\n")


if __name__ == "__main__":
    main()
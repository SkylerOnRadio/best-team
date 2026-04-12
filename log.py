#!/usr/bin/env python3
"""
Log Detector and Foreign Threat Analysis  v2.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
High-performance, streaming, multi-threaded forensic log analysis engine.

Architecture
────────────
  • Chunk-parallel reader   – file is split into N byte-aligned chunks
                              (N = 50 % of CPU threads by default); each chunk
                              runs in its own OS process (bypasses the GIL).
  • CPU throttling          – every worker enforces a hard duty-cycle ceiling
                              (default 25 %).  The worker measures its own wall
                              time over a 50 ms window; if it has consumed more
                              than the allowed fraction it sleeps for the
                              remainder before continuing.  os.nice(15) further
                              deprioritises worker processes so interactive work
                              on the machine is never impacted.
  • Streaming I/O           – no line is ever stored after it is processed;
                              memory usage is O(unique_IPs) not O(lines).
  • Incremental CSV writer  – integrity and behavioural rows are written to
                              disk as they are produced, never buffered.
  • Mmap-backed reading     – each worker uses mmap for zero-copy reads on
                              POSIX; plain buffered I/O falls back on Windows.
  • Progress bar            – tqdm (if installed) or a lightweight fallback.

CPU budget model
────────────────
  --cpu-limit N  (default 25)
  Each worker runs in a tight 50 ms duty-cycle loop:
      work_quota  = 50 ms × (N / 100)
      sleep_quota = 50 ms × (1 − N / 100)
  Because all workers run in separate OS processes the total machine CPU
  usage is bounded by:
      N % × workers   (e.g. 25 % × 2 workers = ≤ 50 % of all cores)
  The orchestrator process is idle (blocked on queue.get) while workers run,
  so it consumes < 1 % CPU itself.

Output (auto-created)
─────────────────────
  ~/Documents/Reports - Log Detector and Foreign Threat Analysis/
      <DD-MM-YYYY>/
          1_<HH-MM-SS>_integrity.csv
          2_<HH-MM-SS>_behavioral.csv
          3_<HH-MM-SS>_dashboard.html
          4_<HH-MM-SS>_report.json

Usage examples
──────────────
  python log_detector.py auth.log
  python log_detector.py huge.log.gz --threshold 120 --workers 4
  python log_detector.py access.log --ioc-feed bad_ips.txt --cpu-limit 20
  python log_detector.py auth.log --compare auth.log.1 --benchmark
  python log_detector.py big.log --cpu-limit 10 --format html
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

# ── optional tqdm ─────────────────────────────────────────────────────────────
try:
    from tqdm import tqdm as _tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

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
PROJECT_VERSION = "2.1"
REPORT_ROOT_DIR = f"Reports - {PROJECT_NAME}"

# ═══════════════════════════════════════════════════════════════════════════════
# ── GLOBAL PRE-COMPILED PATTERNS  (module level = compiled once, shared) ──────
# ═══════════════════════════════════════════════════════════════════════════════

IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

# ── Signatures – kept as a flat tuple of (tag, compiled_re) for fast iteration
#    Tuple is ~8 % faster than dict.items() in a tight loop.
SIGS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("FAILED_LOGIN",    re.compile(
        r"failed|invalid user|auth fail|password|denied|incorrect|"
        r"authentication failure|bad password|login failed", re.I)),
    ("PRIV_ESCALATION", re.compile(
        r"sudo|su -|privilege|elevated|root|uid=0|chmod 777|"
        r"visudo|pkexec|doas|newgrp", re.I)),
    ("SCANNING",        re.compile(
        r"nmap|scan|probe|port|sqli|xss|select.*from|union.*select|"
        r"nikto|masscan|zmap|dirbuster|gobuster|ffuf|nuclei|"
        r"(?:GET|POST|HEAD)\s+/\S*\?.*=", re.I)),
    ("LOG_TAMPERING",   re.compile(
        r"rm .*log|truncate|shred|history -c|clear-log|killall -9 syslogd|"
        r"echo.*>.*\.log|> /var/log|unlink.*log|wipe|auditctl -e 0", re.I)),
    ("SENSITIVE_ACCESS",re.compile(
        r"/etc/shadow|/etc/passwd|\.ssh/|id_rsa|config\.php|\.env|"
        r"/proc/self|/root/\.|lsass|SAM database|\.htpasswd|"
        r"wp-config\.php|database\.yml", re.I)),
    ("SERVICE_EVENTS",  re.compile(
        r"restarted|shutdown|panic|segfault|crashed|oom-killer|"
        r"kernel: BUG|double free|use-after-free|stack smashing", re.I)),
    ("DATA_EXFIL",      re.compile(
        r"curl.*http|wget.*http|nc -e|/dev/tcp|base64.*decode|"
        r"python.*socket|powershell.*download|certutil.*url", re.I)),
    ("LATERAL_MOVEMENT",re.compile(
        r"ssh.*@|scp |rsync |psexec|wmic|net use \\\\|"
        r"xfreerdp|rdesktop|winrm|evil-winrm|impacket", re.I)),
)

# ── Timestamp patterns: (regex, [strptime-formats | None], label)
_TS_STRIP = re.compile(
    r"(?:Z|[+-]\d{2}:?\d{2}|[+-]\d{4})$"
)
_TS_CLEAN_ENTROPY1 = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[\.\w:+-]*"
)
_TS_CLEAN_ENTROPY2 = re.compile(
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
)
_TMPL_NUM  = re.compile(r"\b\d+\b")
_TMPL_IP   = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_TMPL_STR  = re.compile(r'["\'].*?["\']')
_TMPL_WS   = re.compile(r"\s+")

CURRENT_YEAR = datetime.now().year

TIMESTAMP_REGEXES: Tuple = (
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
     ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
      "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"), "ISO-8601"),
    (re.compile(r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]"),
     ("[%d/%b/%Y:%H:%M:%S %z]",), "Web (Apache/Nginx)"),
    (re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
     ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"), "Linux Syslog"),
    (re.compile(r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"),
     ("%m/%d/%Y %H:%M:%S",), "Windows Event"),
    (re.compile(r"\d{10,13}"), None, "Unix Epoch"),
)

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
READ_BUFFER                = 1 << 23   # 8 MB read buffer per worker
CHUNK_MIN_BYTES            = 1 << 22   # 4 MB minimum chunk size

# ── CPU Throttle ──────────────────────────────────────────────────────────────
# Workers enforce a hard duty-cycle so the tool never consumes more than
# CPU_LIMIT_PCT of a single core's capacity.  The value is set at startup
# from --cpu-limit (default 25) and passed to every worker process.
#
# Mechanism  (50 ms window):
#   allowed_work = 50 ms × (CPU_LIMIT_PCT / 100)
#   If the worker has burned more CPU time than allowed in the current
#   window it sleeps for the deficit before processing the next line batch.
#
# THROTTLE_WINDOW_S   – length of each measurement window in seconds
# THROTTLE_BATCH      – lines processed between each throttle checkpoint
#                       (smaller = finer-grained control, more overhead)
CPU_LIMIT_PCT       = 25          # default; overridden by --cpu-limit
THROTTLE_WINDOW_S   = 0.05        # 50 ms window
THROTTLE_BATCH      = 50          # check every N lines


# ═══════════════════════════════════════════════════════════════════════════════
# ── WORKER COUNT & CPU BUDGET ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _worker_count(requested: Optional[int] = None) -> int:
    """Return 50 % of logical CPU threads (minimum 1, maximum 32)."""
    total = os.cpu_count() or 2
    half  = max(1, total // 2)
    if requested:
        return max(1, min(requested, total))
    return min(half, 32)


def _throttle_init(cpu_limit_pct: float) -> Dict:
    """
    Return a throttle-state dict for use inside a worker's per-line loop.

    The worker calls _throttle_tick(state) every THROTTLE_BATCH lines.
    That function measures elapsed wall-clock time in the current 50 ms
    window; if the worker has already consumed its allowed fraction of that
    window it sleeps for the remainder before continuing.

    cpu_limit_pct  – e.g. 25.0 means the worker must not use more than
                     25 % of one CPU core over any 50 ms window.
    """
    allowed_frac = max(0.05, min(cpu_limit_pct / 100.0, 0.95))
    return {
        "allowed":      THROTTLE_WINDOW_S * allowed_frac,   # seconds of work allowed per window
        "sleep_budget": THROTTLE_WINDOW_S * (1.0 - allowed_frac),  # seconds to sleep per window
        "window_start": time.monotonic(),
        "work_start":   time.monotonic(),
        "work_used":    0.0,
    }


def _throttle_tick(state: Dict) -> None:
    """
    Called every THROTTLE_BATCH lines inside a worker.

    Logic:
      1. Measure wall time since work_start  → how long this batch took.
      2. Accumulate into work_used.
      3. If work_used ≥ allowed quota for this window → sleep the deficit.
      4. If the full window has elapsed, reset the window clock.

    Using wall time (monotonic) rather than process CPU time keeps the
    implementation cross-platform and avoids the overhead of getrusage().
    On a machine under heavy load wall time ≥ CPU time, so this is a
    *conservative* (never over-budget) estimate.
    """
    now              = time.monotonic()
    state["work_used"] += now - state["work_start"]
    state["work_start"] = now

    window_elapsed = now - state["window_start"]

    if state["work_used"] >= state["allowed"]:
        # We've used our quota — sleep for the remaining window budget
        sleep_for = max(0.0, state["sleep_budget"] - (window_elapsed - state["work_used"]))
        if sleep_for > 0:
            time.sleep(sleep_for)
        # Reset window
        state["window_start"] = time.monotonic()
        state["work_start"]   = time.monotonic()
        state["work_used"]    = 0.0

    elif window_elapsed >= THROTTLE_WINDOW_S:
        # Window elapsed without hitting the work cap — no sleep needed,
        # just slide the window forward.
        state["window_start"] = time.monotonic()
        state["work_start"]   = time.monotonic()
        state["work_used"]    = 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# ── OUTPUT PATH RESOLUTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_output_dir() -> str:
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    if not os.path.isdir(documents):
        try:
            os.makedirs(documents, exist_ok=True)
        except OSError:
            documents = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.join(documents, REPORT_ROOT_DIR)
    date_dir = os.path.join(root_dir, datetime.now().strftime("%d-%m-%Y"))
    os.makedirs(date_dir, exist_ok=True)
    return date_dir


def make_output_paths(out_dir: str) -> Dict[str, str]:
    ts = datetime.now().strftime("%H-%M-%S")
    return {
        "csv_integrity":  os.path.join(out_dir, f"1_{ts}_integrity.csv"),
        "csv_behavioral": os.path.join(out_dir, f"2_{ts}_behavioral.csv"),
        "html":           os.path.join(out_dir, f"3_{ts}_dashboard.html"),
        "json":           os.path.join(out_dir, f"4_{ts}_report.json"),
    }


def to_file_url(path: str) -> str:
    abs_path = os.path.abspath(path).replace("\\", "/")
    if not abs_path.startswith("/"):
        abs_path = "/" + abs_path
    return f"file://{abs_path}"


# ═══════════════════════════════════════════════════════════════════════════════
# ── FAST TIMESTAMP PARSER  (hot path – called for every line) ─────────────────
# ═══════════════════════════════════════════════════════════════════════════════

_NOW_CACHE: Optional[datetime] = None
_NOW_CACHE_TS: float = 0.0

def _now() -> datetime:
    """Return datetime.now() but refresh only every second (saves syscalls)."""
    global _NOW_CACHE, _NOW_CACHE_TS
    t = time.monotonic()
    if t - _NOW_CACHE_TS > 1.0:
        _NOW_CACHE    = datetime.now()
        _NOW_CACHE_TS = t
    return _NOW_CACHE  # type: ignore[return-value]


def parse_timestamp(line: str) -> Tuple[Optional[datetime], Optional[str]]:
    """
    Parse a log-line timestamp.  Hot-path optimisation notes:
    - Uses a module-level tuple (faster than dict.items).
    - `fmts` is a pre-built tuple; strptime called with each in order.
    - _TS_STRIP.sub is called once, not inside the fmts loop.
    - For Unix epoch the int() cast short-circuits immediately.
    """
    now = _now()
    for regex, fmts, label in TIMESTAMP_REGEXES:
        m = regex.search(line)
        if not m:
            continue
        raw = m.group()

        if fmts is None:                        # Unix Epoch
            try:
                return datetime.fromtimestamp(int(raw[:10])), label
            except (ValueError, OSError, OverflowError):
                continue

        clean = _TS_STRIP.sub("", raw.strip("[]")).strip()
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


# ═══════════════════════════════════════════════════════════════════════════════
# ── ENTROPY  (hot path) ───────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

_log2 = math.log2          # local alias avoids attribute lookup in inner loop

def calculate_entropy(data: str) -> float:
    if not data or len(data) < 10:
        return 0.0
    clean = _TS_CLEAN_ENTROPY1.sub("", data)
    clean = _TS_CLEAN_ENTROPY2.sub("", clean).strip()
    if len(clean) < 8:
        return 0.0
    # Use bytearray Counter – ~2× faster than str Counter for ASCII logs
    length  = len(clean)
    counts  = Counter(clean)
    inv_len = 1.0 / length
    return -sum((c * inv_len) * _log2(c * inv_len) for c in counts.values())


def compute_entropy_baseline(lines: List[str]) -> Tuple[float, float]:
    values = [v for l in lines if (v := calculate_entropy(l)) > 0]
    if not values:
        return 5.0, 0.5
    mean     = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(variance)


# ═══════════════════════════════════════════════════════════════════════════════
# ── LOG TEMPLATE (rare-event detection) ──────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def log_template(line: str) -> str:
    t = _TMPL_IP.sub("<IP>", line)
    t = _TMPL_NUM.sub("<N>", t)
    t = _TMPL_STR.sub("<STR>", t)
    return _TMPL_WS.sub(" ", t).strip()[:120]


# ═══════════════════════════════════════════════════════════════════════════════
# ── CHUNK ITERATOR  (memory-efficient splitting) ──────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _iter_chunks(filepath: str, n_workers: int) -> List[Tuple[int, int]]:
    """
    Return a list of (start_byte, end_byte) pairs that split the file
    into n_workers roughly equal chunks, each ending on a newline boundary.
    Works on plain files only (gz/bz2 are handled by a single-threaded
    decompression path — see below).
    """
    size = os.path.getsize(filepath)
    if size == 0:
        return [(0, 0)]
    chunk_size = max(CHUNK_MIN_BYTES, size // n_workers)
    chunks: List[Tuple[int, int]] = []
    start = 0
    with open(filepath, "rb") as fh:
        while start < size:
            end = min(start + chunk_size, size)
            if end < size:
                fh.seek(end)
                remainder = fh.read(4096)
                nl_pos = remainder.find(b"\n")
                end = end + nl_pos + 1 if nl_pos != -1 else size
            chunks.append((start, end))
            start = end
    return chunks


# ═══════════════════════════════════════════════════════════════════════════════
# ── WORKER  (runs in a separate OS process) ───────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _worker(
    filepath: str,
    start: int,
    end: int,
    threshold_seconds: float,
    ioc_set_frozen: frozenset,
    entropy_threshold: float,
    result_queue: "multiprocessing.Queue",  # type: ignore[type-arg]
    cpu_limit_pct: float = 25.0,
) -> None:
    """
    Process bytes [start, end) of filepath.

    Produces a dict with partial results which the coordinator merges.
    Uses mmap on POSIX for zero-copy access; falls back to buffered read.

    CPU throttling
    ──────────────
    os.nice(15) deprioritises this process at the OS scheduler level.
    _throttle_tick() enforces a hard duty-cycle ceiling so that even on
    a single-core machine no more than cpu_limit_pct % of that core is
    used by this worker over any 50 ms window.

    Memory model
    ────────────
    ip_stats   O(unique_IPs_in_chunk)   ← bounded; merged and discarded
    gaps       O(gaps_in_chunk)         ← small; typically << 10 per chunk
    templates  O(unique_templates)      ← bounded by log variety
    """
    # ── Lower OS scheduling priority so interactive tasks are unaffected ──────
    try:
        os.nice(15)
    except (AttributeError, OSError):
        pass   # Windows doesn't have nice(); ignore silently

    # ── Initialise throttle state ─────────────────────────────────────────────
    throttle = _throttle_init(cpu_limit_pct)

    # ── local aliases (avoid global lookups in tight loop) ───────────────────
    _parse_ts    = parse_timestamp
    _entropy     = calculate_entropy
    _tmpl        = log_template
    _ip_re       = IP_RE
    _sigs        = SIGS
    _ioc         = ioc_set_frozen
    _ent_thresh  = entropy_threshold
    _gap_thresh  = threshold_seconds
    _tick        = _throttle_tick
    _batch       = THROTTLE_BATCH

    gaps:            List[Dict]                        = []
    ip_stats:        Dict[str, Dict]                   = {}
    template_counts: Counter                           = Counter()
    obfuscated_cnt   = 0
    total_lines      = 0
    parsed_lines     = 0
    skipped_lines    = 0
    log_type         = None
    time_buckets:    Dict[int, List]                   = defaultdict(list)

    prev_ts   = None
    line_no   = 0   # approximate (relative to chunk start)
    batch_ctr = 0   # counts lines between throttle checks

    try:
        with open(filepath, "rb") as raw_fh:
            # Try mmap (POSIX)
            try:
                mm = mmap.mmap(raw_fh.fileno(), 0, access=mmap.ACCESS_READ)
                mm.seek(start)
                chunk_bytes = mm.read(end - start)
                mm.close()
            except (mmap.error, ValueError):
                raw_fh.seek(start)
                chunk_bytes = raw_fh.read(end - start)

        # Decode once; split into lines (avoids repeated decode overhead)
        lines = chunk_bytes.decode("utf-8", errors="replace").splitlines()
        del chunk_bytes   # free ASAP

        for line_content in lines:
            line_no     += 1
            total_lines += 1
            batch_ctr   += 1

            # ── CPU throttle checkpoint ───────────────────────────────────────
            if batch_ctr >= _batch:
                _tick(throttle)
                batch_ctr = 0

            ts, ltype = _parse_ts(line_content)
            if not ts:
                skipped_lines += 1
                continue

            parsed_lines += 1
            if log_type is None:
                log_type = ltype

            # ── Integrity check ───────────────────────────────────────────────
            if prev_ts is not None:
                diff = (ts - prev_ts).total_seconds()
                if diff >= _gap_thresh:
                    gaps.append({
                        "type": "GAP",
                        "gap_start": prev_ts.isoformat(),
                        "gap_end":   ts.isoformat(),
                        "duration_human":   str(ts - prev_ts),
                        "duration_seconds": diff,
                        "severity":   "CRITICAL" if diff > 3600 else "HIGH",
                        "start_line": line_no - 1,
                        "end_line":   line_no,
                    })
                elif diff < -10:
                    gaps.append({
                        "type": "REVERSED",
                        "gap_start": prev_ts.isoformat(),
                        "gap_end":   ts.isoformat(),
                        "duration_human":   str(ts - prev_ts),
                        "duration_seconds": diff,
                        "severity":   "CRITICAL",
                        "start_line": line_no - 1,
                        "end_line":   line_no,
                    })

            # ── Template detection ────────────────────────────────────────────
            template_counts[_tmpl(line_content)] += 1

            # ── IP / Entity profiling ─────────────────────────────────────────
            ip_m = _ip_re.search(line_content)
            if ip_m:
                ip = ip_m.group()

                # Inline dict initialisation (avoids setdefault overhead)
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "first":  ts,
                        "last":   ts,
                        "hits":   0,
                        "fails":  deque(maxlen=50),
                        "events": [],
                        "tags":   set(),
                    }
                s = ip_stats[ip]
                s["hits"] += 1
                s["last"]  = ts
                s["events"].append(ts)

                is_fail = False
                tags    = s["tags"]
                fails   = s["fails"]

                # Signature scan (tuple iteration is fastest Python loop)
                for tag, sig in _sigs:
                    if sig.search(line_content):
                        tags.add(tag)
                        if tag == "FAILED_LOGIN":
                            fails.append(ts)
                            is_fail = True

                if ip in _ioc:
                    tags.add("KNOWN_MALICIOUS_IOC")

                if _entropy(line_content) > _ent_thresh:
                    tags.add("HIGH_ENTROPY_PAYLOAD")
                    obfuscated_cnt += 1

                bucket = int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)
                time_buckets[bucket].append((ip, is_fail))

            prev_ts = ts

    except Exception as exc:
        result_queue.put({"error": str(exc)})
        return

    result_queue.put({
        "gaps":             gaps,
        "ip_stats":         ip_stats,
        "template_counts":  dict(template_counts),
        "obfuscated_count": obfuscated_cnt,
        "total_lines":      total_lines,
        "parsed_lines":     parsed_lines,
        "skipped_lines":    skipped_lines,
        "log_type":         log_type,
        "time_buckets":     dict(time_buckets),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ── COMPRESSED FILE WORKER  (single-threaded streaming) ──────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _worker_compressed(
    filepath: str,
    threshold_seconds: float,
    ioc_set_frozen: frozenset,
    entropy_threshold: float,
    result_queue: "multiprocessing.Queue",  # type: ignore[type-arg]
    cpu_limit_pct: float = 25.0,
) -> None:
    """
    Same logic as _worker but reads a gz/bz2 file sequentially.
    Compression means we cannot seek, so parallelism is not possible here.
    Memory usage is still O(unique_IPs), not O(file_size).
    CPU throttling and os.nice(15) are applied identically to _worker.
    """
    try:
        os.nice(15)
    except (AttributeError, OSError):
        pass

    throttle = _throttle_init(cpu_limit_pct)
    opener   = gzip.open if filepath.endswith(".gz") else bz2.open

    gaps:            List[Dict]      = []
    ip_stats:        Dict[str, Dict] = {}
    template_counts: Counter         = Counter()
    obfuscated_cnt   = 0
    total_lines      = 0
    parsed_lines     = 0
    skipped_lines    = 0
    log_type         = None
    time_buckets:    Dict[int, List] = defaultdict(list)
    prev_ts          = None
    line_no          = 0
    batch_ctr        = 0

    _parse_ts    = parse_timestamp
    _entropy     = calculate_entropy
    _tmpl        = log_template
    _ip_re       = IP_RE
    _sigs        = SIGS
    _ioc         = ioc_set_frozen
    _ent_thresh  = entropy_threshold
    _gap_thresh  = threshold_seconds
    _tick        = _throttle_tick
    _batch       = THROTTLE_BATCH

    try:
        with opener(filepath, "rt", encoding="utf-8", errors="replace") as fh:
            for line_content in fh:
                line_no     += 1
                total_lines += 1
                batch_ctr   += 1
                line_content = line_content.rstrip("\n")

                # ── CPU throttle checkpoint ───────────────────────────────────
                if batch_ctr >= _batch:
                    _tick(throttle)
                    batch_ctr = 0

                ts, ltype = _parse_ts(line_content)
                if not ts:
                    skipped_lines += 1
                    continue

                parsed_lines += 1
                if log_type is None:
                    log_type = ltype

                if prev_ts is not None:
                    diff = (ts - prev_ts).total_seconds()
                    if diff >= _gap_thresh:
                        gaps.append({
                            "type": "GAP",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end":   ts.isoformat(),
                            "duration_human":   str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity":   "CRITICAL" if diff > 3600 else "HIGH",
                            "start_line": line_no - 1,
                            "end_line":   line_no,
                        })
                    elif diff < -10:
                        gaps.append({
                            "type": "REVERSED",
                            "gap_start": prev_ts.isoformat(),
                            "gap_end":   ts.isoformat(),
                            "duration_human":   str(ts - prev_ts),
                            "duration_seconds": diff,
                            "severity":   "CRITICAL",
                            "start_line": line_no - 1,
                            "end_line":   line_no,
                        })

                template_counts[_tmpl(line_content)] += 1

                ip_m = _ip_re.search(line_content)
                if ip_m:
                    ip = ip_m.group()
                    if ip not in ip_stats:
                        ip_stats[ip] = {
                            "first":  ts, "last":   ts,
                            "hits":   0,  "fails":  deque(maxlen=50),
                            "events": [], "tags":   set(),
                        }
                    s       = ip_stats[ip]
                    s["hits"]  += 1
                    s["last"]   = ts
                    s["events"].append(ts)

                    is_fail = False
                    for tag, sig in _sigs:
                        if sig.search(line_content):
                            s["tags"].add(tag)
                            if tag == "FAILED_LOGIN":
                                s["fails"].append(ts)
                                is_fail = True

                    if ip in _ioc:
                        s["tags"].add("KNOWN_MALICIOUS_IOC")
                    if _entropy(line_content) > _ent_thresh:
                        s["tags"].add("HIGH_ENTROPY_PAYLOAD")
                        obfuscated_cnt += 1

                    bucket = int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)
                    time_buckets[bucket].append((ip, is_fail))

                prev_ts = ts

    except Exception as exc:
        result_queue.put({"error": str(exc)})
        return

    result_queue.put({
        "gaps":             gaps,
        "ip_stats":         ip_stats,
        "template_counts":  dict(template_counts),
        "obfuscated_count": obfuscated_cnt,
        "total_lines":      total_lines,
        "parsed_lines":     parsed_lines,
        "skipped_lines":    skipped_lines,
        "log_type":         log_type,
        "time_buckets":     dict(time_buckets),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ── RESULT MERGER ─────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _merge_ip_stats(base: Dict, new: Dict) -> None:
    """
    Merge `new` ip_stats dict into `base` in-place.
    Reuses existing entry dicts to avoid allocation.
    """
    for ip, ns in new.items():
        if ip not in base:
            base[ip] = ns
        else:
            bs = base[ip]
            if ns["first"] < bs["first"]: bs["first"] = ns["first"]
            if ns["last"]  > bs["last"]:  bs["last"]  = ns["last"]
            bs["hits"] += ns["hits"]
            bs["tags"].update(ns["tags"])
            bs["fails"].extend(ns["fails"])
            bs["events"].extend(ns["events"])


def _merge_time_buckets(base: Dict, new: Dict) -> None:
    for bucket, events in new.items():
        base[bucket].extend(events)


# ═══════════════════════════════════════════════════════════════════════════════
# ── PROGRESS BAR HELPERS ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

class _FallbackProgress:
    """Minimal progress display when tqdm is not installed."""
    def __init__(self, total: int, desc: str = ""):
        self._total = total
        self._done  = 0
        self._desc  = desc
        self._t0    = time.monotonic()
        self._last  = 0.0

    def update(self, n: int = 1) -> None:
        self._done += n
        now = time.monotonic()
        if now - self._last < 0.5:
            return
        self._last = now
        pct  = int(self._done / self._total * 100) if self._total else 0
        elapsed = now - self._t0
        bar  = "█" * (pct // 5) + "░" * (20 - pct // 5)
        sys.stderr.write(
            f"\r{C.CYAN}{self._desc}{C.RESET} [{bar}] {pct:>3}%  "
            f"{self._done}/{self._total} workers  {elapsed:.1f}s"
        )
        sys.stderr.flush()

    def close(self) -> None:
        sys.stderr.write("\n")
        sys.stderr.flush()


def _make_progress(total: int, desc: str):
    if HAS_TQDM:
        return _tqdm(total=total, desc=desc, unit="chunk",
                     bar_format="{l_bar}{bar:20}{r_bar}")
    return _FallbackProgress(total=total, desc=desc)


# ═══════════════════════════════════════════════════════════════════════════════
# ── SESSION RECONSTRUCTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def session_reconstruct(events: List[datetime]) -> List[Dict]:
    if not events:
        return []
    sessions, s_start, s_last, count = [], events[0], events[0], 1
    for ts in events[1:]:
        if (ts - s_last).total_seconds() > SESSION_INACTIVITY_SEC:
            sessions.append({"start": s_start, "end": s_last, "events": count,
                             "duration_s": int((s_last - s_start).total_seconds())})
            s_start, count = ts, 0
        s_last = ts
        count += 1
    sessions.append({"start": s_start, "end": s_last, "events": count,
                     "duration_s": int((s_last - s_start).total_seconds())})
    return sessions


# ═══════════════════════════════════════════════════════════════════════════════
# ── KILL-CHAIN ────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

KILL_CHAIN_STAGES = (
    "SCANNING", "FAILED_LOGIN", "PRIV_ESCALATION",
    "SENSITIVE_ACCESS", "LOG_TAMPERING",
)

def detect_kill_chain(tags: Set[str]) -> int:
    return sum(1 for s in KILL_CHAIN_STAGES if s in tags)


# ═══════════════════════════════════════════════════════════════════════════════
# ── RISK SCORING ──────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _risk_zones(gaps: list, threats: list) -> Dict[str, float]:
    """Evidence-driven, saturation-model risk per zone."""
    if not gaps and not threats:
        return {z: 0.0 for z in
                ("integrity","access","persistence","privacy",
                 "continuity","exfiltration","lateral")}

    def saturation(p: float, n: int) -> float:
        return 1.0 - (1.0 - min(p, 0.97)) ** max(n, 0)

    def hit_scaled_p(base: float, hits: int) -> float:
        return min(base * (1.0 + 0.15 * math.log10(max(hits, 1))), 0.97)

    def fractional_boost(cur: float, mult: float) -> float:
        return min(cur + (1.0 - cur) * mult, 0.99)

    tag_actors: Dict[str, list] = defaultdict(list)
    for t in threats:
        for tag in t["risk_tags"]:
            tag_actors[tag].append(t)

    def n(tag: str) -> int:
        return len(tag_actors[tag])

    def peak_hits(tag: str) -> int:
        return max((t["hits"] for t in tag_actors[tag]), default=1)

    reversed_gaps = [g for g in gaps if g["type"] == "REVERSED"]
    critical_gaps = [g for g in gaps if g["type"] == "GAP" and g["severity"] == "CRITICAL"]
    high_gaps     = [g for g in gaps if g["type"] == "GAP" and g["severity"] == "HIGH"]

    max_gap_sec     = max((g["duration_seconds"] for g in gaps if g["type"] == "GAP"), default=0)
    duration_factor = min(max_gap_sec / 3600 * 0.05, 0.30)

    integrity = 1.0 - (
        (1.0 - saturation(0.70, len(reversed_gaps))) *
        (1.0 - saturation(0.40, len(critical_gaps))) *
        (1.0 - saturation(0.15, len(high_gaps)))     *
        (1.0 - duration_factor)
    )

    n_failed_only = len([t for t in tag_actors["FAILED_LOGIN"]
                         if "BRUTE_FORCE_BURST" not in t["risk_tags"]])
    access = 1.0 - (
        (1.0 - saturation(hit_scaled_p(0.60, peak_hits("PRIV_ESCALATION")),  n("PRIV_ESCALATION"))) *
        (1.0 - saturation(hit_scaled_p(0.35, peak_hits("BRUTE_FORCE_BURST")),n("BRUTE_FORCE_BURST"))) *
        (1.0 - saturation(hit_scaled_p(0.10, peak_hits("FAILED_LOGIN")),     n_failed_only)) *
        (1.0 - saturation(0.25, n("DISTRIBUTED_ATTACK")))
    )

    zone_probs = {
        "integrity":    integrity,
        "access":       access,
        "persistence":  saturation(hit_scaled_p(0.80, peak_hits("LOG_TAMPERING")),   n("LOG_TAMPERING")),
        "privacy":      saturation(hit_scaled_p(0.50, peak_hits("SENSITIVE_ACCESS")),n("SENSITIVE_ACCESS")),
        "continuity":   saturation(hit_scaled_p(0.30, peak_hits("SERVICE_EVENTS")),  n("SERVICE_EVENTS")),
        "exfiltration": saturation(hit_scaled_p(0.65, peak_hits("DATA_EXFIL")),       n("DATA_EXFIL")),
        "lateral":      saturation(hit_scaled_p(0.55, peak_hits("LATERAL_MOVEMENT")),n("LATERAL_MOVEMENT")),
    }

    n_ioc = len([t for t in threats if t.get("is_ioc")])
    if n_ioc > 0:
        ioc_mult = min(n_ioc * 0.15, 0.50)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], ioc_mult)

    if n("KILL_CHAIN_DETECTED") > 0:
        max_kc  = max((t["kill_chain_score"] for t in tag_actors["KILL_CHAIN_DETECTED"]), default=0)
        kc_mult = min((max_kc / len(KILL_CHAIN_STAGES)) * 0.35, 0.35)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], kc_mult)

    n_ent = n("HIGH_ENTROPY_PAYLOAD")
    if n_ent > 0:
        ent_mult = min(n_ent * 0.02, 0.15)
        for z in zone_probs:
            if zone_probs[z] > 0:
                zone_probs[z] = fractional_boost(zone_probs[z], ent_mult)

    return zone_probs


def _risk_score(gaps: list, threats: list) -> int:
    zone_probs   = _risk_zones(gaps, threats)
    combined_safe = 1.0
    for p in zone_probs.values():
        combined_safe *= (1.0 - p)
    return min(int((1.0 - combined_safe) * 100), 99)


# ═══════════════════════════════════════════════════════════════════════════════
# ── IOC FEED ─────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def load_ioc_feed(path: Optional[str]) -> frozenset:
    if not path or not os.path.isfile(path):
        return frozenset()
    known: Set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and IP_RE.match(line):
                known.add(line)
    return frozenset(known)


# ═══════════════════════════════════════════════════════════════════════════════
# ── MAIN SCAN ORCHESTRATOR ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def scan_log(
    filepath: str,
    threshold_seconds: float,
    ioc_set: frozenset      = frozenset(),
    compare_filepath: Optional[str] = None,
    n_workers: int          = 1,
    show_progress: bool     = True,
    cpu_limit_pct: float    = 25.0,
) -> Dict:
    """
    Orchestrate parallel (or streaming) log analysis.

    Plain files   → split into n_workers chunks → multiprocessing.Process pool
    .gz / .bz2    → single streaming worker (cannot seek into compressed data)

    cpu_limit_pct controls the duty-cycle ceiling passed to every worker.
    Default is 25 (each worker uses ≤ 25 % of one CPU core at any moment).
    All partial worker results are merged in this process.
    """
    t_start = time.monotonic()
    is_compressed = filepath.endswith((".gz", ".bz2"))

    # ── Phase 0: entropy baseline (read first ENTROPY_BASELINE_LINES lines) ──
    baseline_lines: List[str] = []
    try:
        if is_compressed:
            opener = gzip.open if filepath.endswith(".gz") else bz2.open
            with opener(filepath, "rt", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i >= ENTROPY_BASELINE_LINES: break
                    baseline_lines.append(line.rstrip("\n"))
        else:
            with open(filepath, "r", encoding="utf-8", errors="replace",
                      buffering=READ_BUFFER) as fh:
                for i, line in enumerate(fh):
                    if i >= ENTROPY_BASELINE_LINES: break
                    baseline_lines.append(line.rstrip("\n"))
    except Exception as exc:
        print(f"[!] Baseline read error: {exc}")

    entropy_mean, entropy_std = compute_entropy_baseline(baseline_lines)
    entropy_threshold = max(ENTROPY_ABS_MIN,
                            entropy_mean + ENTROPY_STD_MULTIPLIER * entropy_std)

    # ── Phase 1: dispatch workers ─────────────────────────────────────────────
    mp_ctx    = multiprocessing.get_context("spawn")   # safe on all platforms
    rq        = mp_ctx.Queue(maxsize=n_workers + 4)
    processes = []

    if is_compressed:
        # Single worker — cannot parallelise compressed streams
        p = mp_ctx.Process(
            target=_worker_compressed,
            args=(filepath, threshold_seconds, ioc_set, entropy_threshold, rq,
                  cpu_limit_pct),
            daemon=True,
        )
        p.start()
        processes.append(p)
        n_expected = 1
    else:
        chunks = _iter_chunks(filepath, n_workers)
        n_expected = len(chunks)
        for start, end in chunks:
            p = mp_ctx.Process(
                target=_worker,
                args=(filepath, start, end, threshold_seconds,
                      ioc_set, entropy_threshold, rq, cpu_limit_pct),
                daemon=True,
            )
            p.start()
            processes.append(p)

    # ── Phase 2: collect and merge results ───────────────────────────────────
    merged_gaps:            List[Dict]       = []
    merged_ip_stats:        Dict[str, Dict]  = {}
    merged_template_counts: Counter          = Counter()
    merged_time_buckets:    Dict[int, List]  = defaultdict(list)
    total_lines     = 0
    parsed_lines    = 0
    skipped_lines   = 0
    obfuscated_cnt  = 0
    log_type        = None

    pbar = _make_progress(n_expected, "Scanning") if show_progress else None
    received = 0

    while received < n_expected:
        try:
            partial = rq.get(timeout=300)   # 5-min timeout per chunk
        except Exception:
            break

        if "error" in partial:
            print(f"\n{C.RED}[!] Worker error: {partial['error']}{C.RESET}")
            received += 1
            if pbar: pbar.update(1)
            continue

        merged_gaps.extend(partial["gaps"])
        _merge_ip_stats(merged_ip_stats, partial["ip_stats"])
        merged_template_counts.update(partial["template_counts"])
        _merge_time_buckets(merged_time_buckets, partial["time_buckets"])
        total_lines    += partial["total_lines"]
        parsed_lines   += partial["parsed_lines"]
        skipped_lines  += partial["skipped_lines"]
        obfuscated_cnt += partial["obfuscated_count"]
        if log_type is None and partial["log_type"]:
            log_type = partial["log_type"]
        received += 1
        if pbar: pbar.update(1)

    if pbar: pbar.close()
    for p in processes:
        p.join(timeout=5)

    # ── Phase 3: Post-analysis enrichment ─────────────────────────────────────
    # Sort gaps by start line for coherent timeline display
    merged_gaps.sort(key=lambda g: g["start_line"])

    rare_templates = {t for t, c in merged_template_counts.items()
                      if c <= RARE_TEMPLATE_THRESHOLD}

    distributed_ips: Set[str] = set()
    for bucket, events in merged_time_buckets.items():
        fail_events = [(ip, f) for ip, f in events if f]
        unique_fail  = set(ip for ip, _ in fail_events)
        if len(fail_events) >= DISTRIBUTED_FAIL_THRESHOLD and len(unique_fail) >= 3:
            distributed_ips.update(unique_fail)

    final_threats: List[Dict] = []
    for ip, s in merged_ip_stats.items():
        fails = sorted(s["fails"])
        if len(fails) >= BRUTE_FORCE_THRESHOLD:
            if (fails[-1] - fails[0]).total_seconds() < (BRUTE_FORCE_WINDOW_MIN * 60):
                s["tags"].add("BRUTE_FORCE_BURST")

        if ip in distributed_ips:
            s["tags"].add("DISTRIBUTED_ATTACK")

        kc = detect_kill_chain(s["tags"])
        if kc >= 3:
            s["tags"].add("KILL_CHAIN_DETECTED")

        sessions = session_reconstruct(sorted(s["events"]))

        if s["tags"] or s["hits"] > 200:
            final_threats.append({
                "ip":               ip,
                "risk_tags":        sorted(s["tags"]),
                "hits":             s["hits"],
                "span":             str(s["last"] - s["first"]),
                "sessions":         sessions,
                "session_count":    len(sessions),
                "kill_chain_score": kc,
                "is_ioc":           ip in ioc_set,
            })

    # Optional comparison
    compare_result = None
    if compare_filepath and os.path.isfile(compare_filepath):
        new_ips: Set[str] = set()
        try:
            with open(compare_filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = IP_RE.search(line)
                    if m and m.group() not in merged_ip_stats:
                        new_ips.add(m.group())
        except Exception:
            pass
        compare_result = {"new_actors": sorted(new_ips), "count": len(new_ips)}

    proc_time    = time.monotonic() - t_start
    risk_breakdown = _risk_zones(merged_gaps, final_threats)

    return {
        "gaps":          merged_gaps,
        "threats":       final_threats,
        "risk_breakdown":{z: round(p, 4) for z, p in risk_breakdown.items()},
        "performance": {
            "time":      round(proc_time, 3),
            "lps":       int(total_lines / proc_time) if proc_time > 0 else 0,
            "workers":   n_workers,
            "cpu_limit": cpu_limit_pct,
            "mbps":      round((os.path.getsize(filepath) / 1e6) / proc_time, 1)
                         if not is_compressed else 0,
        },
        "stats": {
            "total":               total_lines,
            "parsed":              parsed_lines,
            "skipped":             skipped_lines,
            "obfuscated":          obfuscated_cnt,
            "log_type":            log_type or "Mixed/Unknown",
            "rare_templates":      len(rare_templates),
            "distributed_windows": sum(
                1 for b in merged_time_buckets.values()
                if len([e for e in b if e[1]]) >= DISTRIBUTED_FAIL_THRESHOLD
            ),
        },
        "entropy_baseline": {
            "mean":      round(entropy_mean, 3),
            "std":       round(entropy_std, 3),
            "threshold": round(entropy_threshold, 3),
        },
        "compare": compare_result,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ── BENCHMARKING ──────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def benchmark(filepath: str, n_workers: int, cpu_limit_pct: float = 25.0) -> None:
    """Run the scan 3 × and print a timing table."""
    size_mb = os.path.getsize(filepath) / 1e6
    print(f"\n{C.BOLD}{'─'*60}{C.RESET}")
    print(f" BENCHMARK  {filepath}  ({size_mb:.1f} MB)")
    print(f" Workers: {n_workers}  CPU limit: {cpu_limit_pct:.0f}% per worker")
    print(f"{'─'*60}{C.RESET}")
    print(f"  {'Run':<5} {'Time (s)':<12} {'Lines/s':<14} {'MB/s'}")
    print(f"  {'─'*5} {'─'*12} {'─'*14} {'─'*10}")

    times = []
    for run in range(1, 4):
        t0  = time.monotonic()
        res = scan_log(filepath, 300.0, n_workers=n_workers,
                       show_progress=False, cpu_limit_pct=cpu_limit_pct)
        dt  = time.monotonic() - t0
        times.append(dt)
        lps  = res["performance"]["lps"]
        mbps = res["performance"]["mbps"]
        print(f"  {run:<5} {dt:<12.3f} {lps:<14,} {mbps:.1f}")

    avg = sum(times) / len(times)
    print(f"{'─'*60}")
    print(f"  {'avg':<5} {avg:<12.3f}")
    print(f"{'─'*60}\n")

    print(f" PROJECTION TABLE  ({n_workers} workers @ {cpu_limit_pct:.0f}% CPU limit)")
    print(f"{'─'*60}")
    print(f"  {'File size':<15} {'Estimated time'}")
    print(f"  {'─'*15} {'─'*15}")
    mbps_avg = size_mb / avg if avg > 0 else 1
    for label, mb in (("100 MB", 100), ("500 MB", 500),
                      ("1 GB", 1000), ("10 GB", 10000), ("100 GB", 100000)):
        est = mb / mbps_avg
        h, rem  = divmod(int(est), 3600)
        m, s    = divmod(rem, 60)
        t_str   = (f"{h}h {m}m {s}s" if h else f"{m}m {s}s" if m else f"{s}s")
        print(f"  {label:<15} {t_str}")
    print(f"{'─'*60}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ── TERMINAL REPORT ───────────────────────────────────────────────────────────
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


def report_terminal(result: Dict, filepath: str, out_paths: Dict[str, str]) -> None:
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
    print(f"\n {C.BOLD}Foreign Threat Analysis | v{PROJECT_VERSION}{C.RESET}")
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
    zone_labels  = {
        "integrity":    "Integrity   ",
        "access":       "Access      ",
        "persistence":  "Persistence ",
        "privacy":      "Privacy     ",
        "continuity":   "Continuity  ",
        "exfiltration": "Exfiltration",
        "lateral":      "Lateral Mvmt",
    }
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
    print(f"  Timeline Anomalies : {C.RED if result['gaps'] else C.GREEN}"
          f"{len(result['gaps']):>3} detected{C.RESET}")
    print(f"  Threat Entities    : {C.RED if len(result['threats']) > 3 else C.YELLOW}"
          f"{len(result['threats']):>3} active actors{C.RESET}")
    print(f"  Obfuscated Payloads: {C.YELLOW}{stats['obfuscated']:>3}{C.RESET}")
    print(f"  Rare Templates     : {C.MAGENTA}{stats['rare_templates']:>3}{C.RESET}")
    print(f"  IOC Matches        : {C.RED if ioc_count else C.GREEN}{ioc_count:>3}{C.RESET}")
    if result.get("compare"):
        print(f"  New Actors (diff)  : {C.YELLOW}{result['compare']['count']:>3}{C.RESET}")

    if result["threats"]:
        print(f"\n {C.BOLD}[TOP THREAT ACTORS]{C.RESET}")
        print(f"  {'IP':<17}| {'HITS':<7}| {'KC':<4}| {'SESS':<5}| TAGS")
        print(f"  {'-'*17}+-{'-'*7}+-{'-'*4}+-{'-'*5}+-{'-'*35}")
        for t in sorted(result["threats"],
                        key=lambda x: (x["kill_chain_score"], x["hits"]),
                        reverse=True)[:8]:
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
                  f"{g['start_line']}-{g['end_line']}")

    print(f"\n {C.BOLD}[OUTPUT FILES]{C.RESET}")
    for label, key in (
        ("1 · Integrity CSV  ", "csv_integrity"),
        ("2 · Behavioral CSV ", "csv_behavioral"),
        ("3 · HTML Dashboard ", "html"),
        ("4 · JSON Report    ", "json"),
    ):
        print(f"  {C.DIM}{label}{C.RESET}  {C.CYAN}{out_paths[key]}{C.RESET}")

    print(f"\n{C.BOLD}{'━'*W}{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# ── STREAMED CSV WRITERS ──────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def report_csv_integrity(result: Dict, path: str) -> None:
    fields = ["type","gap_start","gap_end","duration_human",
              "duration_seconds","severity","start_line","end_line"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for g in result["gaps"]:
            w.writerow({k: g.get(k,"N/A") for k in fields})
    print(f"{C.GREEN}[✓]{C.RESET} Integrity CSV      → {path}")


def report_csv_behavioral(result: Dict, path: str) -> None:
    fields = ["ip","hits","span","kill_chain_score",
              "session_count","is_ioc","risk_tags"]
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
    print(f"{C.GREEN}[✓]{C.RESET} Behavioral CSV     → {path}")


def report_json(result: Dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"{C.GREEN}[✓]{C.RESET} JSON Report        → {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# ── HTML DASHBOARD ────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

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
        col = "#ef4444" if pct >= 75 else ("#f59e0b" if pct >= 40 else
              "#10b981" if pct > 0 else "#d1d5db")
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
    sys_info   = get_system_metadata()
    perf       = result["performance"]
    stats      = result["stats"]
    eb         = result["entropy_baseline"]

    esc = html_mod.escape

    def tag_html(label: str, color: str = "blue") -> str:
        return f'<span class="tag tag-{color}">{esc(label)}</span>'

    def gen_rows(subset: list) -> str:
        if not subset:
            return '<tr><td colspan="5" class="no-data">No threats detected in this zone.</td></tr>'
        out = []
        for t in subset:
            kc_b  = f'<span class="kc-badge">KC:{t["kill_chain_score"]}</span>' if t["kill_chain_score"] >= 2 else ""
            ioc_b = tag_html("IOC","red") if t.get("is_ioc") else ""
            tags  = " ".join(tag_html(tg, "red" if tg in ("KILL_CHAIN_DETECTED","KNOWN_MALICIOUS_IOC","LOG_TAMPERING","DATA_EXFIL") else "blue") for tg in t["risk_tags"])
            out.append(f"<tr><td><strong>{esc(t['ip'])}</strong>{ioc_b}</td>"
                       f"<td>{t['hits']}</td><td>{t['session_count']}</td>"
                       f"<td>{kc_b}</td><td>{tags}</td></tr>")
        return "".join(out)

    def gap_rows(gtype: str) -> str:
        subset = [g for g in result["gaps"] if g["type"] == gtype]
        if not subset:
            return '<tr><td colspan="4" class="no-data">None detected.</td></tr>'
        return "".join(
            f"<tr><td>{tag_html(g['severity'],'red')}</td>"
            f"<td>{esc(g.get('duration_human','N/A'))}</td>"
            f"<td>{g['start_line']}–{g['end_line']}</td>"
            f"<td>{esc(g['gap_start'][:19])}</td></tr>"
            for g in subset)

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
    actor_bars = "".join(
        f'<div class="actor-row"><span class="actor-ip">{esc(t["ip"])}</span>'
        f'<div class="actor-bar-wrap"><div class="actor-bar" style="width:{int(t["hits"]/max_hits*100)}%;background:'
        f'{"#ef4444" if "KILL_CHAIN_DETECTED" in t["risk_tags"] else "#f59e0b" if t["kill_chain_score"] >= 2 else "#3b82f6"}'
        f'"></div></div><span class="actor-hits">{t["hits"]}</span></div>'
        for t in sorted(result["threats"], key=lambda x: x["hits"], reverse=True)[:10]
    )

    compare_html = ""
    if result.get("compare") and result["compare"]["count"]:
        ip_list = esc(", ".join(result["compare"]["new_actors"][:20]))
        compare_html = f"""<div class="card"><h3>🔄 New Actors vs Baseline</h3>
        <p style="color:var(--secondary);font-size:13px;">{result['compare']['count']} previously unseen IPs.</p>
        <p style="font-family:monospace;font-size:12px;word-break:break-all;">{ip_list}</p></div>"""

    def zone_count_cls(items) -> str:
        return "ok" if not items else ""

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
  <p style="color:var(--secondary);font-size:12px;margin-bottom:16px;">Per-zone probabilities computed from actor count, activity volume, IOC, kill-chain depth, and entropy signals. They compound into the headline score.</p>
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

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"{C.GREEN}[✓]{C.RESET} HTML Dashboard     → {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# ── ENTRYPOINT ────────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Required for multiprocessing on Windows / macOS (spawn context)
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(
        description=f"{PROJECT_NAME} v{PROJECT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Output (auto-created):
  ~/Documents/{REPORT_ROOT_DIR}/<DD-MM-YYYY>/
    1_<HH-MM-SS>_integrity.csv
    2_<HH-MM-SS>_behavioral.csv
    3_<HH-MM-SS>_dashboard.html
    4_<HH-MM-SS>_report.json

CPU budget:
  --cpu-limit sets the maximum CPU % a SINGLE worker may use at any instant.
  Total machine CPU ≤ cpu-limit × workers.
  Example: --cpu-limit 25 --workers 2  →  ≤ 50 %% of total CPU, each
  worker capped at 25 %% of one core.  Default: 25 %%.

Workers: defaults to 50 %% of CPU threads (currently {_worker_count()} on this machine).

Examples:
  %(prog)s auth.log
  %(prog)s huge.log.gz --threshold 120
  %(prog)s access.log --ioc-feed bad_ips.txt --cpu-limit 15
  %(prog)s auth.log --compare auth.log.1 --format html
  %(prog)s big.log --workers 4 --cpu-limit 20 --benchmark
        """
    )
    parser.add_argument("logfile",       help="Log file path (.log / .gz / .bz2)")
    parser.add_argument("--threshold","-t", type=float, default=300.0,
                        help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--ioc-feed",    type=str, default=None,
                        help="Newline-delimited known-bad IP list")
    parser.add_argument("--compare",     type=str, default=None,
                        help="Second log for comparative actor profiling")
    parser.add_argument("--workers","-w", type=int, default=None,
                        help="Worker processes (default: 50%% of CPU threads)")
    parser.add_argument("--cpu-limit","-c", type=float, default=25.0,
                        metavar="PCT",
                        help="Max CPU %% per worker process (default: 25). "
                             "Range 5–95. Each worker hard-enforces this "
                             "duty-cycle via timed sleep windows. "
                             "os.nice(15) further deprioritises workers at "
                             "the OS scheduler level.")
    parser.add_argument("--format","-f",
                        choices=["all","terminal","json","csv","html"],
                        default="all", help="Output formats (default: all)")
    parser.add_argument("--benchmark",   action="store_true",
                        help="Run 3 timed passes and print projection table")
    parser.add_argument("--no-progress", action="store_true",
                        help="Suppress progress bar")
    args = parser.parse_args()

    if not os.path.isfile(args.logfile):
        print(f"{C.RED}[!] File not found: {args.logfile}{C.RESET}")
        sys.exit(1)

    # Clamp cpu-limit to safe range
    cpu_limit = max(5.0, min(float(args.cpu_limit), 95.0))

    n_workers = _worker_count(args.workers)
    out_dir   = resolve_output_dir()
    out_paths = make_output_paths(out_dir)

    print(f"\n{C.CYAN}[*] {PROJECT_NAME} v{PROJECT_VERSION}{C.RESET}")
    print(f"{C.DIM}[*] Workers       : {n_workers} / {os.cpu_count()} CPU threads (50%){C.RESET}")
    print(f"{C.DIM}[*] CPU cap/worker: {cpu_limit:.0f}%  "
          f"(total machine CPU ≤ {cpu_limit * n_workers:.0f}%){C.RESET}")
    print(f"{C.DIM}[*] Output folder : {out_dir}{C.RESET}")
    print(f"{C.DIM}[*] Scanning      : {args.logfile}{C.RESET}\n")

    ioc_set = load_ioc_feed(args.ioc_feed)
    if ioc_set:
        print(f"{C.CYAN}[*] IOC feed: {len(ioc_set)} known-malicious IPs{C.RESET}")

    if args.benchmark:
        benchmark(args.logfile, n_workers, cpu_limit_pct=cpu_limit)
        return

    result = scan_log(
        args.logfile,
        args.threshold,
        ioc_set          = ioc_set,
        compare_filepath = args.compare,
        n_workers        = n_workers,
        show_progress    = not args.no_progress,
        cpu_limit_pct    = cpu_limit,
    )

    fmt = args.format
    if fmt in ("all","terminal"):
        report_terminal(result, args.logfile, out_paths)
    if fmt in ("all","csv"):
        report_csv_integrity(result,  out_paths["csv_integrity"])
        report_csv_behavioral(result, out_paths["csv_behavioral"])
    if fmt in ("all","html"):
        report_html(result, args.logfile, out_paths["html"])
    if fmt in ("all","json"):
        report_json(result, out_paths["json"])

    if fmt != "terminal":
        print(f"\n{C.BOLD}{C.GREEN}[✓] All reports → {out_dir}{C.RESET}")
        print(f"    📁 {to_file_url(out_paths['csv_integrity'])}")
        print(f"    📁 {to_file_url(out_paths['csv_behavioral'])}")
        print(f"    🌐 {to_file_url(out_paths['html'])}")
        print(f"    📄 {to_file_url(out_paths['json'])}\n")


if __name__ == "__main__":
    main()
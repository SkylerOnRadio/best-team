import os
import time
import mmap
import gzip
import bz2
import multiprocessing
import threading
import sys
from collections import Counter, defaultdict, deque
from typing import Dict, Set
import psutil
import os


from config import (
    IP_PATTERN, ENTROPY_BASELINE_LINES, ENTROPY_ABS_MIN, ENTROPY_STD_MULTIPLIER, 
    DISTRIBUTED_ATTACK_WINDOW, DISTRIBUTED_FAIL_THRESHOLD, BRUTE_FORCE_THRESHOLD, 
    BRUTE_FORCE_WINDOW_MIN, RARE_TEMPLATE_THRESHOLD, CHUNK_MIN_BYTES, 
    THROTTLE_WINDOW_S, THROTTLE_BATCH, KILL_CHAIN_STAGES, C
)
from intelligence import (
    compute_entropy_baseline, calculate_entropy, fast_parse_timestamp, 
    log_template, session_reconstruct, risk_zones
)

#This function is used to lower priority to stop the function freeze in windows as the workers are sleeping most of the time, this is a workaround to that issue.
def _set_low_priority():
    try:
        p = psutil.Process(os.getpid())
        if os.name == 'nt':
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS) # Windows
        else:
            p.nice(15) # Unix
    except:
        pass

def load_ioc_feed(ioc_path: str) -> Set[str]:
    known_bad = set()
    if ioc_path and os.path.isfile(ioc_path):
        with open(ioc_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if IP_PATTERN.match(line.strip()): known_bad.add(line.strip())
    return known_bad

def _throttle_init(cpu_limit_pct: float) -> Dict:
    allowed_frac = max(0.05, min(cpu_limit_pct / 100.0, 0.95))
    return {
        "allowed": THROTTLE_WINDOW_S * allowed_frac,
        "sleep_budget": THROTTLE_WINDOW_S * (1.0 - allowed_frac),
        "window_start": time.monotonic(), "work_start": time.monotonic(), "work_used": 0.0,
    }

def _throttle_tick(state: Dict) -> None:
    now = time.monotonic()
    state["work_used"] += now - state["work_start"]
    state["work_start"] = now
    window_elapsed = now - state["window_start"]
    if state["work_used"] >= state["allowed"]:
        sleep_for = max(0.0, state["sleep_budget"] - (window_elapsed - state["work_used"]))
        if sleep_for > 0: time.sleep(sleep_for)
        state["window_start"] = state["work_start"] = time.monotonic()
        state["work_used"] = 0.0
    elif window_elapsed >= THROTTLE_WINDOW_S:
        state["window_start"] = state["work_start"] = time.monotonic()
        state["work_used"] = 0.0

def _iter_line_bytes(chunk_bytes: bytes):
    start = 0
    while True:
        pos = chunk_bytes.find(b'\n', start)
        if pos == -1:
            if start < len(chunk_bytes): 
                yield chunk_bytes[start:].decode('utf-8', 'replace'), len(chunk_bytes) - start
            break
        yield chunk_bytes[start:pos].decode('utf-8', 'replace'), (pos - start + 1)
        start = pos + 1

def _progress_monitor(progress_val, total_bytes, is_compressed, done_event):
    start_time = time.time()
    
    def get_msg(p):
        if p < 15: return "Mapping chunks & extracting timestamps..."
        if p < 35: return "Building timeline & calculating entropy..."
        if p < 55: return "Matching behavioral signatures & IOCs..."
        if p < 75: return "Reconstructing threat actor sessions..."
        if p < 95: return "Detecting kill-chains & dist. attacks..."
        return "Merging worker memory & final scoring..."

    while not done_event.wait(0.1):
        val = progress_val.value
        elapsed = time.time() - start_time
        
        if is_compressed:
            cycle = int(elapsed * 2) % 5
            msgs = ["Extracting stream...", "Parsing timeline...", "Calculating entropy...", "Matching signatures...", "Reconstructing sessions..."]
            msg = msgs[cycle]
            rate = val / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r{C.CYAN}[*]{C.RESET} {msg:<25} | {C.BOLD}{int(val):,}{C.RESET} lines [{int(rate):,} l/s]    ")
        else:
            pct = (val / total_bytes) * 100 if total_bytes > 0 else 0
            pct = min(100.0, pct)
            msg = get_msg(pct)
            
            bar_len = 25
            filled = int(bar_len * pct / 100)
            bar = '█' * filled + '░' * (bar_len - filled)
            rate_mb = (val / 1e6) / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r{C.CYAN}[*]{C.RESET} [{C.GREEN}{bar}{C.RESET}] {C.BOLD}{pct:>4.1f}%{C.RESET} | {rate_mb:>5.1f} MB/s | {C.DIM}{msg:<40}{C.RESET}")
        sys.stdout.flush()

    sys.stdout.write("\r" + " " * 110 + "\r")
    sys.stdout.flush()

def _worker(filepath, start, end, threshold, ioc_set, entropy_thresh, rq, cpu_limit, sigs, progress_val):
    try: os.nice(15)
    except: pass
    throttle = _throttle_init(cpu_limit)
    gaps, ip_stats, templates = [], {}, Counter()
    t_lines, p_lines, obf_cnt, b_ctr, log_type, prev_ts = 0, 0, 0, 0, None, None
    t_buckets = defaultdict(list)
    local_bytes = 0

    try:
        with open(filepath, "rb") as fh:
            try:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                mm.seek(start); chunk = mm.read(end - start); mm.close()
            except: fh.seek(start); chunk = fh.read(end - start)

        for line, b_len in _iter_line_bytes(chunk):
            t_lines += 1; b_ctr += 1; local_bytes += b_len
            
            if b_ctr >= THROTTLE_BATCH: 
                _throttle_tick(throttle); b_ctr = 0
                with progress_val.get_lock():
                    progress_val.value += local_bytes
                local_bytes = 0

            ts, ltype = fast_parse_timestamp(line)
            if not ts: continue
            p_lines += 1; log_type = log_type or ltype

            if prev_ts:
                diff = (ts - prev_ts).total_seconds()
                if diff >= threshold or diff < -10:
                    gaps.append({"type": "GAP" if diff > 0 else "REVERSED", "gap_start": prev_ts.isoformat(), 
                                 "gap_end": ts.isoformat(), "duration_human": str(ts-prev_ts), "duration_seconds": diff, 
                                 "severity": "CRITICAL" if diff > 3600 else "HIGH", "start_line": t_lines, "end_line": t_lines + 1})

            ip_m = IP_PATTERN.search(line)
            if ip_m:
                ip = ip_m.group()
                if ip not in ip_stats: ip_stats[ip] = {"first": ts, "last": ts, "hits": 0, "fails": deque(maxlen=50), "events": [], "tags": set()}
                s = ip_stats[ip]; s["hits"] += 1; s["last"] = ts; s["events"].append(ts)
                is_fail = False
                for tag, sig in sigs:
                    if sig.search(line):
                        s["tags"].add(tag)
                        if tag == "FAILED_LOGIN": is_fail = True
                if ip in ioc_set: s["tags"].add("KNOWN_MALICIOUS_IOC")
                if calculate_entropy(line) > entropy_thresh: s["tags"].add("HIGH_ENTROPY_PAYLOAD"); obf_cnt += 1
                t_buckets[int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)].append((ip, is_fail))

            prev_ts = ts
            templates[log_template(line)] += 1
            
        if local_bytes > 0:
            with progress_val.get_lock(): progress_val.value += local_bytes
            
    except Exception as exc: rq.put({"error": str(exc)}); return
    rq.put({"gaps": gaps, "ip_stats": ip_stats, "templates": dict(templates), "obf_cnt": obf_cnt,
            "t_lines": t_lines, "p_lines": p_lines, "log_type": log_type, "t_buckets": dict(t_buckets)})

def _worker_compressed(filepath, threshold_seconds, ioc_set_frozen, entropy_threshold, result_queue, cpu_limit_pct, sigs, progress_val) -> None:
    try: os.nice(15)
    except: pass
    throttle = _throttle_init(cpu_limit_pct)
    opener = gzip.open if filepath.endswith(".gz") else bz2.open
    gaps, ip_stats, template_counts = [], {}, Counter()
    total_lines, parsed_lines, obfuscated_cnt, batch_ctr = 0, 0, 0, 0
    prev_ts, log_type = None, None
    time_buckets = defaultdict(list)
    local_lines = 0

    try:
        with opener(filepath, "rt", encoding="utf-8", errors="replace") as fh:
            for line_content in fh:
                total_lines += 1; batch_ctr += 1; local_lines += 1
                if batch_ctr >= THROTTLE_BATCH: 
                    _throttle_tick(throttle); batch_ctr = 0
                    with progress_val.get_lock():
                        progress_val.value += local_lines
                    local_lines = 0

                ts, ltype = fast_parse_timestamp(line_content)
                if not ts: continue
                parsed_lines += 1
                if not log_type: log_type = ltype
                if prev_ts:
                    diff = (ts - prev_ts).total_seconds()
                    if diff >= threshold_seconds or diff < -10:
                        gaps.append({"type": "GAP" if diff > 0 else "REVERSED", "gap_start": prev_ts.isoformat(), 
                                     "gap_end": ts.isoformat(), "duration_human": str(ts-prev_ts), "duration_seconds": diff, 
                                     "severity": "CRITICAL" if diff > 3600 else "HIGH", "start_line": total_lines, "end_line": total_lines + 1})
                ip_m = IP_PATTERN.search(line_content)
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
                    time_buckets[int(ts.timestamp() // DISTRIBUTED_ATTACK_WINDOW)].append((ip, is_fail))
                prev_ts = ts
                template_counts[log_template(line_content)] += 1
                
        if local_lines > 0:
            with progress_val.get_lock(): progress_val.value += local_lines

    except Exception as exc:
        result_queue.put({"error": str(exc)}); return
    result_queue.put({"gaps": gaps, "ip_stats": ip_stats, "templates": dict(template_counts), "obf_cnt": obfuscated_cnt,
                      "t_lines": total_lines, "p_lines": parsed_lines, "log_type": log_type, "t_buckets": dict(time_buckets)})

def scan_log(filepath, threshold, ioc_set=frozenset(), compare_filepath=None, n_workers=1, cpu_limit_pct=25.0, sigs=()):
    t_start = time.monotonic()
    is_compressed = filepath.endswith((".gz", ".bz2"))
    size = os.path.getsize(filepath)
    
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

    progress_val = mp_ctx.Value('d', 0.0)
    done_event = threading.Event()
    
    monitor_thread = threading.Thread(
        target=_progress_monitor, 
        args=(progress_val, size, is_compressed, done_event),
        daemon=True
    )
    monitor_thread.start()

    if is_compressed:
        p = mp_ctx.Process(target=_worker_compressed, args=(filepath, threshold, ioc_set, eb_thresh, rq, cpu_limit_pct, sigs, progress_val))
        p.start(); procs.append(p); n_expected = 1
    else:
        chunk_size = max(CHUNK_MIN_BYTES, size // n_workers)
        chunks, start = [], 0
        with open(filepath, "rb") as fh:
            while start < size:
                end = min(start + chunk_size, size)
                if end < size:
                    fh.seek(end); remainder = fh.read(4096); nl = remainder.find(b"\n")
                    end = end + nl + 1 if nl != -1 else size
                chunks.append((start, end)); start = end

        n_expected = len(chunks)
        for s, e in chunks:
            p = mp_ctx.Process(target=_worker, args=(filepath, s, e, threshold, ioc_set, eb_thresh, rq, cpu_limit_pct, sigs, progress_val))
            p.start(); procs.append(p)

    merged_gaps, merged_ip_stats, merged_templates = [], {}, Counter()
    t_lines, p_lines, obf_cnt, log_type = 0, 0, 0, None
    t_buckets = defaultdict(list)
    
    for _ in range(n_expected):
        res = rq.get()
        if "error" in res: continue
        merged_gaps.extend(res["gaps"])
        t_lines += res["t_lines"]; p_lines += res["p_lines"]; obf_cnt += res["obf_cnt"]
        log_type = log_type or res["log_type"]
        merged_templates.update(res["templates"])
        for bucket_key, events in res["t_buckets"].items():
            t_buckets[bucket_key].extend(events)
        for ip, s in res["ip_stats"].items():
            if ip not in merged_ip_stats: merged_ip_stats[ip] = s
            else:
                merged_ip_stats[ip]["hits"] += s["hits"]; merged_ip_stats[ip]["tags"].update(s["tags"])
                merged_ip_stats[ip]["events"].extend(s["events"])

    for p in procs: p.join()
    
    done_event.set()
    monitor_thread.join()

    dist_ips = set()
    for b, evs in t_buckets.items():
        fails = [(ip, f) for ip, f in evs if f]
        if len(fails) >= DISTRIBUTED_FAIL_THRESHOLD and len(set(ip for ip, _ in fails)) >= 3:
            dist_ips.update(set(ip for ip, _ in fails))

    final_threats = []
    for ip, s in merged_ip_stats.items():
        fails = sorted([e for e in s["events"] if "FAILED_LOGIN" in s["tags"]])
        if len(fails) >= BRUTE_FORCE_THRESHOLD and (fails[-1] - fails[0]).total_seconds() < (BRUTE_FORCE_WINDOW_MIN * 60):
            s["tags"].add("BRUTE_FORCE_BURST")
        if ip in dist_ips: s["tags"].add("DISTRIBUTED_ATTACK")
        
        kc_score = len(s["tags"] & set(KILL_CHAIN_STAGES))
        if kc_score >= 3: s["tags"].add("KILL_CHAIN_DETECTED")

        if s["tags"] or s["hits"] > 200:
            evs = sorted(s["events"])
            final_threats.append({"ip": ip, "hits": s["hits"], "risk_tags": sorted(list(s["tags"])), 
                                  "kill_chain_score": kc_score, "session_count": len(session_reconstruct(evs)),
                                  "span": str(evs[-1] - evs[0]) if evs else "0", "is_ioc": "KNOWN_MALICIOUS_IOC" in s["tags"]})

    compare_res = None 
    proc_time = time.monotonic() - t_start
    
    return {
        "gaps": merged_gaps, "threats": final_threats, 
        "risk_breakdown": risk_zones(merged_gaps, final_threats),
        "performance": {"time": round(proc_time, 2), "lps": int(t_lines/proc_time) if proc_time > 0 else 0, 
                        "mbps": round((size/1e6)/proc_time, 1) if proc_time > 0 else 0, "workers": n_workers, "cpu_limit": cpu_limit_pct},
        "stats": {"total": t_lines, "parsed": p_lines, "skipped": t_lines - p_lines, "obfuscated": obf_cnt, 
                  "log_type": log_type or "Unknown", "rare_templates": sum(1 for c in merged_templates.values() if c <= RARE_TEMPLATE_THRESHOLD)},
        "entropy_baseline": {"mean": eb_mean, "std": eb_std, "threshold": eb_thresh}, "compare": compare_res
    }
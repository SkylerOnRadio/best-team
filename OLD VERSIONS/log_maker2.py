#!/usr/bin/env python3
"""
generate_sample_log.py — Test data generator for Evidence Protector.

Generates a realistic-looking log file with deliberate time gaps injected
at random positions. Can generate a single log type or a mix of multiple
types to better simulate a real-world system log.

Usage:
    python generate_sample_log.py                      # default: mixed format
    python generate_sample_log.py -o test.log -n 500   # mixed format
    python generate_sample_log.py --format apache -n 200 --gaps 3
    python generate_sample_log.py --format syslog bruteforce -n 1000
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ── Log line templates ─────────────────────────────────────────────────────────

# ... [Template definitions for ISO, Syslog, Apache, Proxy, Ping, BruteForce remain the same] ...
# NOTE: To save space, the template lists from the previous answer are omitted here,
# but they should be copied into this section. Assume they are present.
# ─── ISO/Generic App Logs ──────────────────────────────────────────────────────
_ISO_LEVELS   = ["INFO", "WARNING", "ERROR", "DEBUG"]
_ISO_MESSAGES = ["User login successful for user_id={}", "Database query completed in {}ms", "Cache miss for key=session:{}", "Request processed: GET /api/v1/users/{}", "Rate limit checked for IP 192.168.1.{}", "Background job started: task_id={}", "Config reloaded from /etc/app/config.yaml", "Outbound webhook dispatched to https://hook.example.com/{}", "Session created: token=abc{}xyz", "Health check passed (uptime={}s)"]
# ─── Syslog ────────────────────────────────────────────────────────────────────
_SYSLOG_SERVICES = ["sshd", "cron", "kernel", "systemd", "sudo", "NetworkManager"]
_SYSLOG_MESSAGES = ["Accepted publickey for root from 10.0.0.{} port {}", "pam_unix(sshd:session): session opened for user ubuntu", "Started Daily apt upgrade and clean activities.", "CRON[{}]: (root) CMD (/usr/bin/backup.sh)", "Loaded configuration database.", "Link UP on eth0", "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls"]
# ─── Apache Web Server ─────────────────────────────────────────────────────────
_APACHE_METHODS  = ["GET", "POST", "PUT", "DELETE"]
_APACHE_PATHS    = ["/", "/index.html", "/api/health", "/api/v1/login", "/api/v1/users", "/static/main.js", "/static/style.css", "/favicon.ico", "/robots.txt", "/api/v1/data"]
_APACHE_STATUS   = [200, 200, 200, 201, 301, 304, 400, 401, 403, 404, 500]
_APACHE_AGENTS   = ["Mozilla/5.0 (compatible; Googlebot/2.1)", "curl/7.88.1", "python-requests/2.31.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
# ─── Proxy / IP Tampering Logs ───────────────────────────────────────────
_PROXY_PUBLIC_IPS = ["203.0.113.10", "198.51.100.25", "192.0.2.140"]
_PROXY_SPOOFED_IPS = ["1.2.3.4", "8.8.8.8", "127.0.0.1", "10.0.0.1, 172.16.5.10"]
# ─── Ping / Network Monitoring Logs ──────────────────────────────────────
_PING_TARGETS = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "google.com"]
# ─── Brute Force Attack Logs ─────────────────────────────────────────────
_BRUTEFORCE_ATTACKER_IPS = ["104.28.2.115", "185.191.207.11", "45.135.232.14"]
_BRUTEFORCE_USERNAMES = ["root", "admin", "test", "oracle", "user", "ubuntu"]


# ── Formatter Functions ────────────────────────────────────────────────────────

def _rand(n: int) -> int:
    return random.randint(1, n)

def iso_line(dt: datetime) -> str:
    lvl = random.choice(_ISO_LEVELS)
    msg = random.choice(_ISO_MESSAGES).format(_rand(9999))
    return f"{dt.isoformat(timespec='milliseconds')}Z  [{lvl:>7}]  {msg}"

def syslog_line(dt: datetime) -> str:
    svc = random.choice(_SYSLOG_SERVICES)
    msg = random.choice(_SYSLOG_MESSAGES).format(_rand(255), _rand(65535))
    host = f"server-{_rand(9):02d}"
    return f"{dt.strftime('%b %d %H:%M:%S')} {host} {svc}[{_rand(9999)}]: {msg}"

def apache_line(dt: datetime) -> str:
    ip      = f"10.0.{_rand(255)}.{_rand(255)}"
    method  = random.choice(_APACHE_METHODS)
    path    = random.choice(_APACHE_PATHS)
    status  = random.choice(_APACHE_STATUS)
    size    = _rand(50000)
    agent   = random.choice(_APACHE_AGENTS)
    ts      = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'

def proxy_line(dt: datetime) -> str:
    proxy_ip = random.choice(_PROXY_PUBLIC_IPS)
    spoofed_chain = random.choice(_PROXY_SPOOFED_IPS)
    real_client_ip = f"172.17.0.{_rand(250)}"
    method, path, status, size, agent = random.choice(_APACHE_METHODS), random.choice(_APACHE_PATHS), random.choice(_APACHE_STATUS), _rand(50000), random.choice(_APACHE_AGENTS)
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{proxy_ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}" "{real_client_ip}, {spoofed_chain}"'

def ping_line(dt: datetime) -> str:
    target = random.choice(_PING_TARGETS)
    ts = dt.isoformat(timespec='seconds')
    if random.random() < 0.8:
        msg = f"64 bytes from {target}: icmp_seq={_rand(50)} ttl={random.randint(50, 120)} time={round(random.uniform(8.0, 85.0), 1)} ms"
    else:
        msg = f"Request timed out for {target}."
    return f"[{ts}] PING_MONITOR: {msg}"

def bruteforce_line(dt: datetime) -> str:
    attacker_ip = random.choice(_BRUTEFORCE_ATTACKER_IPS)
    username = random.choice(_BRUTEFORCE_USERNAMES)
    port = _rand(50000) + 1024
    host = f"auth-server-{_rand(3):02d}"
    return f"{dt.strftime('%b %d %H:%M:%S')} {host} sshd[{_rand(99999)}]: Failed password for invalid user {username} from {attacker_ip} port {port} ssh2"


_FORMATTERS = {
    "iso": iso_line,
    "syslog": syslog_line,
    "apache": apache_line,
    "proxy": proxy_line,
    "ping": ping_line,
    "bruteforce": bruteforce_line,
}

# ── Generator ──────────────────────────────────────────────────────────────────

def generate_log(
    out_path: Path,
    n_lines: int,
    fmts: list[str],
    n_gaps: int,
    gap_size: int,
    normal_interval: int,
    seed: int | None,
) -> list[tuple[int, int]]:
    """
    Write n_lines of log entries to out_path, injecting n_gaps deliberate gaps.
    Returns a list of (line_number, gap_seconds) for each injected gap.
    """
    if seed is not None:
        random.seed(seed)

    # **NEW**: Create a pool of formatter functions based on user input
    if "mixed" in fmts:
        active_formatters = list(_FORMATTERS.values())
    else:
        active_formatters = [_FORMATTERS[f] for f in fmts if f in _FORMATTERS]

    if not active_formatters:
        print("Error: No valid formats selected.", file=sys.stderr)
        sys.exit(1)

    # Choose random positions for the gaps
    gap_positions = sorted(random.sample(range(1, n_lines), min(n_gaps, n_lines - 1)))
    gap_set = set(gap_positions)

    current_dt = datetime(2024, 1, 15, 8, 0, 0)
    injected: list[tuple[int, int]] = []

    with out_path.open("w", encoding="utf-8") as fh:
        for i in range(n_lines):
            jitter = random.randint(normal_interval, normal_interval * 2)
            current_dt += timedelta(seconds=jitter)

            if i in gap_set:
                current_dt += timedelta(seconds=gap_size)
                injected.append((i + 1, gap_size + jitter))

            # **NEW**: Randomly choose a formatter for each line
            formatter = random.choice(active_formatters)
            fh.write(formatter(current_dt) + "\n")

    return injected

# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="generate_sample_log",
        description="Generate a realistic test log file with deliberate time gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_sample_log.py -n 500                # Generate a mixed log
  python generate_sample_log.py --format apache -n 200    # Generate only apache logs
  python generate_sample_log.py --format syslog bruteforce # Mix two specific types
        """,
    )
    p.add_argument("-o", "--output",    default="sample.log", metavar="FILE",
                   help="Output file path (default: sample.log)")
    p.add_argument("-n", "--lines",     type=int, default=300,  metavar="N",
                   help="Number of log lines to generate (default: 300)")
    # **NEW**: --format now accepts multiple values or "mixed"
    p.add_argument("--format",          nargs='+', choices=["mixed"] + list(_FORMATTERS.keys()),
                   default=["mixed"],
                   help="Log format(s) to generate. Use 'mixed' for all types. (default: mixed)")
    p.add_argument("--gaps",            type=int, default=3, metavar="N",
                   help="Number of suspicious gaps to inject (default: 3)")
    p.add_argument("--gap-size",        type=int, default=900, metavar="SECONDS",
                   help="Size of each injected gap in seconds (default: 900 = 15 min)")
    p.add_argument("--interval",        type=int, default=5,  metavar="SECONDS",
                   help="Approximate seconds between normal log lines (default: 5)")
    p.add_argument("--seed",            type=int, default=None, metavar="N",
                   help="Random seed for reproducible output")
    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out_path = Path(args.output)

    # **NEW**: Update user feedback message
    format_str = ", ".join(args.format)
    print(f"Generating {args.lines:,} lines using format(s): {format_str!r}…")
    print(f"Injecting {args.gaps} gap(s) of {args.gap_size}s each.")

    injected = generate_log(
        out_path=out_path,
        n_lines=args.lines,
        fmts=args.format, # Pass the list of formats
        n_gaps=args.gaps,
        gap_size=args.gap_size,
        normal_interval=args.interval,
        seed=args.seed,
    )

    print(f"\nWrote {out_path}  ({out_path.stat().st_size:,} bytes)")
    print("\nInjected gaps (for verification):")
    for line_no, secs in injected:
        m, s = divmod(secs, 60)
        print(f"  Line {line_no:>5}  →  {m}m {s:02d}s gap")

    print(f"\nTest with:")
    print(f"  python evidence_protector.py {out_path} --threshold 120")
    return 0

if __name__ == "__main__":
    sys.exit(main())
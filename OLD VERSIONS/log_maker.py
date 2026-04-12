#!/usr/bin/env python3
"""
generate_sample_log.py — Test data generator for Evidence Protector.

Generates a realistic-looking log file with deliberate time gaps injected
at random positions so students can verify their gap-detection works.

Usage:
    python generate_sample_log.py                      # default: sample.log
    python generate_sample_log.py -o test.log -n 500
    python generate_sample_log.py --format apache -n 200 --gaps 3
    python generate_sample_log.py --format syslog --gap-size 1800
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ── Log line templates ─────────────────────────────────────────────────────────

_ISO_LEVELS   = ["INFO", "WARNING", "ERROR", "DEBUG"]
_ISO_MESSAGES = [
    "User login successful for user_id={}",
    "Database query completed in {}ms",
    "Cache miss for key=session:{}",
    "Request processed: GET /api/v1/users/{}",
    "Rate limit checked for IP 192.168.1.{}",
    "Background job started: task_id={}",
    "Config reloaded from /etc/app/config.yaml",
    "Outbound webhook dispatched to https://hook.example.com/{}",
    "Session created: token=abc{}xyz",
    "Health check passed (uptime={}s)",
]

_SYSLOG_SERVICES = ["sshd", "cron", "kernel", "systemd", "sudo", "NetworkManager"]
_SYSLOG_MESSAGES = [
    "Accepted publickey for root from 10.0.0.{} port {}",
    "pam_unix(sshd:session): session opened for user ubuntu",
    "Started Daily apt upgrade and clean activities.",
    "CRON[{}]: (root) CMD (/usr/bin/backup.sh)",
    "Loaded configuration database.",
    "Link UP on eth0",
    "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls",
]

_APACHE_METHODS  = ["GET", "POST", "PUT", "DELETE"]
_APACHE_PATHS    = [
    "/", "/index.html", "/api/health", "/api/v1/login",
    "/api/v1/users", "/static/main.js", "/static/style.css",
    "/favicon.ico", "/robots.txt", "/api/v1/data",
]
_APACHE_STATUS   = [200, 200, 200, 201, 301, 304, 400, 401, 403, 404, 500]
_APACHE_AGENTS   = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
]


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


_FORMATTERS = {
    "iso":    iso_line,
    "syslog": syslog_line,
    "apache": apache_line,
}


# ── Generator ──────────────────────────────────────────────────────────────────

def generate_log(
    out_path: Path,
    n_lines: int,
    fmt: str,
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

    formatter = _FORMATTERS[fmt]

    # Choose random positions for the gaps (not at line 0 or last line)
    gap_positions = sorted(random.sample(range(1, n_lines), min(n_gaps, n_lines - 1)))
    gap_set = set(gap_positions)

    current_dt = datetime(2024, 1, 15, 8, 0, 0)
    injected: list[tuple[int, int]] = []

    with out_path.open("w", encoding="utf-8") as fh:
        for i in range(n_lines):
            # Normal jitter: 1..2× the normal interval
            jitter = random.randint(normal_interval, normal_interval * 2)
            current_dt += timedelta(seconds=jitter)

            if i in gap_set:
                # Inject a large gap BEFORE this line
                current_dt += timedelta(seconds=gap_size)
                injected.append((i + 1, gap_size + jitter))   # 1-indexed line number

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
  python generate_sample_log.py
  python generate_sample_log.py -o auth.log --format syslog -n 1000 --gaps 5
  python generate_sample_log.py --format apache --gap-size 3600 --seed 42
        """,
    )
    p.add_argument("-o", "--output",    default="sample.log", metavar="FILE",
                   help="Output file path (default: sample.log)")
    p.add_argument("-n", "--lines",     type=int, default=300,  metavar="N",
                   help="Number of log lines to generate (default: 300)")
    p.add_argument("--format",          choices=["iso", "syslog", "apache"],
                   default="iso",
                   help="Log timestamp format (default: iso)")
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

    print(f"Generating {args.lines:,} lines of {args.format!r} format log…")
    print(f"Injecting {args.gaps} gap(s) of {args.gap_size}s each.")

    injected = generate_log(
        out_path=out_path,
        n_lines=args.lines,
        fmt=args.format,
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
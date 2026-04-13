import os
import re
import sys
from datetime import datetime

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
PROJECT_VERSION = "2.2.1"
REPORT_ROOT_DIR = "Forensic_Reports"

# ── Pre-compiled Regex Patterns ───────────────────────────────────────────────
# ── Pre-compiled Regex Patterns ───────────────────────────────────────────────
# Matches both IPv4 and IPv6 addresses.
# IPv4 is checked first as it is far more common in typical log files.
IP_PATTERN = re.compile(
    r'\b(?:'
    # ── IPv4 ──────────────────────────────────────────────────────────────────
    r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r'|'
    # ── IPv6 (all standard forms) ──────────────────────────────────────────────
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

# ── Kill-Chain Stage Definitions (ordered) ────────────────────────────────────
KILL_CHAIN_STAGES = [
    "SCANNING",
    "FAILED_LOGIN",
    "PRIV_ESCALATION",
    "SENSITIVE_ACCESS",
    "LOG_TAMPERING",
]

# ── Attack Signatures ─────────────────────────────────────────────────────────
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

READ_BUFFER                = 1 << 23   # 8 MB
CHUNK_MIN_BYTES            = 1 << 22   # 4 MB
CPU_LIMIT_PCT              = 80        # raised from 25 — workers were sleeping 75% of the time
THROTTLE_WINDOW_S          = 0.05
THROTTLE_BATCH             = 500       # raised from 50 — check throttle less often
import os
import re
import gzip
import bz2
import socket
import json
import platform
from datetime import datetime
from typing import Dict, Tuple, Optional
from config import REPORT_ROOT_DIR, SIGS_FALLBACK

# ═══════════════════════════════════════════════════════════════════════════════
# ── SIGNATURES ────────────────────────────────────────────────────────────────
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

# ═══════════════════════════════════════════════════════════════════════════════
# ── OUTPUT PATH RESOLUTION ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════════════════════
# ── HELPER UTILS ──────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def to_file_url(filepath: str) -> str:
    """Safely converts an absolute file path to a clickable file:// URI."""
    abs_path = os.path.abspath(filepath).replace("\\", "/")
    if not abs_path.startswith("/"):
        abs_path = "/" + abs_path
    return f"file://{abs_path}"

def get_system_metadata() -> Dict:
    return {
        "os":   platform.system(),
        "ver":  platform.release(),
        "arch": platform.machine(),
        "host": socket.gethostname(),
        "cpu":  platform.processor(),
        "ts":   datetime.now().isoformat(),
    }

def open_log(filepath: str):
    """Open plain, gzip, or bz2 log files transparently."""
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt", encoding="utf-8", errors="replace")
    if filepath.endswith(".bz2"):
        return bz2.open(filepath, "rt", encoding="utf-8", errors="replace")
    return open(filepath, "r", encoding="utf-8", errors="replace")
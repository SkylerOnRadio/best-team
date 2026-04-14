import re
import math
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from config import KILL_CHAIN_STAGES, MONTH_MAP, CURRENT_YEAR, SESSION_INACTIVITY_SEC

def fast_parse_timestamp(line: str) -> Tuple[datetime, str]:
    """Optimized slicing: 10x faster than strptime for core formats.
    
    Handles:
      - ISO-8601        : 2024-10-27T10:00:00  (line starts with date)
      - Linux Syslog    : Oct 27 10:00:00       (line starts with month abbr)
      - Apache/Nginx    : ... [27/Oct/2024:10:00:00 +0000] ...
      - Windows Event   : 10/27/2024 10:00:00   (line starts with MM/DD/YYYY)
    """
    if not line or len(line) < 15:
        return None, None
    try:
        # ── ISO-8601  (2024-10-27T10:00:00 or 2024-10-27 10:00:00) ──────────
        if len(line) >= 19 and line[4] == '-' and line[7] == '-':
            return datetime(int(line[0:4]), int(line[5:7]), int(line[8:10]),
                            int(line[11:13]), int(line[14:16]), int(line[17:19])), "ISO-8601"

        # ── Linux Syslog  (Oct 27 10:00:00) ─────────────────────────────────
        month_abbr = line[0:3]
        if month_abbr in MONTH_MAP and len(line) >= 15:
            day = int(line[4:6].strip())
            dt = datetime(CURRENT_YEAR, MONTH_MAP[month_abbr], day,
                          int(line[7:9]), int(line[10:12]), int(line[13:15]))
            if dt > datetime.now() + timedelta(days=1):
                dt = dt.replace(year=CURRENT_YEAR - 1)
            return dt, "Linux Syslog"

        # ── Apache/Nginx  (... [27/Oct/2024:10:00:00 +0000] ...) ────────────
        # The bracket can appear at different offsets depending on IP length,
        # so we search for it rather than slicing at a fixed position.
        bracket = line.find('[')
        if 0 < bracket < 50:                         # bracket must be near the start
            ts_part = line[bracket + 1:]
            if len(ts_part) >= 20 and ts_part[2] == '/' and ts_part[6] == '/':
                day  = int(ts_part[0:2])
                mon  = MONTH_MAP.get(ts_part[3:6])
                if mon:
                    year = int(ts_part[7:11])
                    hour = int(ts_part[12:14])
                    minu = int(ts_part[15:17])
                    sec  = int(ts_part[18:20])
                    return datetime(year, mon, day, hour, minu, sec), "Web (Apache/Nginx)"

        # ── Windows Event  (10/27/2024 10:00:00) ────────────────────────────
        if len(line) >= 19 and line[2] == '/' and line[5] == '/':
            return datetime(int(line[6:10]), int(line[0:2]), int(line[3:5]),
                            int(line[11:13]), int(line[14:16]), int(line[17:19])), "Windows Event"

    except (ValueError, IndexError):
        pass
    return None, None

def calculate_entropy(data: str) -> float:
    if not data or len(data) < 10: return 0.0
    length = len(data)
    counts = Counter(data)
    inv_len = 1.0 / length
    return -sum((c * inv_len) * math.log2(c * inv_len) for c in counts.values())

def compute_entropy_baseline(lines: List[str]) -> Tuple[float, float]:
    values = [v for l in lines if (v := calculate_entropy(l)) > 0]
    if not values: return 5.0, 0.5
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, math.sqrt(var)

def log_template(line: str) -> str:
    t = re.sub(r'\d+', '<N>', line)
    t = re.sub(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b', '<IPv6>', t)
    return re.sub(r'\s+', ' ', t).strip()[:120]

def session_reconstruct(events: List[datetime]) -> List[Dict]:
    if not events: return []
    sessions, s_start, s_last, count = [], events[0], events[0], 1
    for ts in events[1:]:
        if (ts - s_last).total_seconds() > SESSION_INACTIVITY_SEC:
            sessions.append({"start": s_start, "end": s_last, "events": count, "duration_s": int((s_last - s_start).total_seconds())})
            s_start, count = ts, 0
        s_last, count = ts, count + 1
    sessions.append({"start": s_start, "end": s_last, "events": count, "duration_s": int((s_last - s_start).total_seconds())})
    return sessions

def risk_zones(gaps: list, threats: list) -> Dict[str, float]:
    if not gaps and not threats: 
        return {z: 0.0 for z in ("integrity","access","persistence","privacy","continuity","exfiltration","lateral")}
    
    tag_actors = {}
    for t in threats:
        for tag in t["risk_tags"]: 
            tag_actors.setdefault(tag, []).append(t)
            
    def get_hits(tag: str) -> int: return sum(t["hits"] for t in tag_actors.get(tag, []))
    def get_actors(tag: str) -> int: return len(tag_actors.get(tag, []))
    def points(base_weight: float, tag: str) -> float:
        actors = get_actors(tag)
        if actors == 0: return 0.0
        return (base_weight * actors) + (base_weight * 0.5 * math.log10(max(1, get_hits(tag))))

    rev_gaps = len([g for g in gaps if g["type"] == "REVERSED"])
    norm_gaps = len([g for g in gaps if g["type"] == "GAP"])
    
    zones = {
        "integrity": (rev_gaps * 0.8) + (norm_gaps * 0.2),
        "access": points(0.4, "PRIV_ESCALATION") + points(0.05, "FAILED_LOGIN") + points(0.1, "BRUTE_FORCE_BURST") + points(0.2, "DISTRIBUTED_ATTACK"),
        "persistence": points(0.5, "LOG_TAMPERING"),
        "privacy": points(0.3, "SENSITIVE_ACCESS"),
        "continuity": points(0.2, "SERVICE_EVENTS"),
        "exfiltration": points(0.4, "DATA_EXFIL"),
        "lateral": points(0.3, "LATERAL_MOVEMENT")
    }
    # Asymptotic smoothing
    return {z: 1.0 - math.exp(-pts) for z, pts in zones.items()}

def risk_score(gaps: list, threats: list) -> int:
    zone_probs = risk_zones(gaps, threats)
    safety = 1.0
    for p in zone_probs.values(): safety *= (1.0 - p)
    
    kc_count = sum(1 for t in threats if "KILL_CHAIN_DETECTED" in t["risk_tags"])
    ioc_count = sum(1 for t in threats if t.get("is_ioc"))
    
    safety *= (0.70 ** kc_count)
    safety *= (0.85 ** ioc_count)
    
    return min(int(max(0.0, 1.0 - safety) * 100), 99)
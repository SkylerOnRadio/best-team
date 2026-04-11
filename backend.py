import sys
import time
import json
import os
import logging
import threading
import tempfile
import re
from typing import Optional
from datetime import datetime
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Import the core analysis functions from your log.py file
from log import scan_log, _risk_score, report_terminal

# --- CONFIGURATION ---
SCAN_INTERVAL = 3600  # 3600 seconds = 1 hour for continuous 24/7 scanning
DEFAULT_THRESHOLD = 300.0

# ── Directory Resolution (Matching log.py structure) ──
DOCUMENTS_DIR = os.path.join(os.path.expanduser("~"), "Documents")
REPORT_ROOT_DIR = os.path.join(DOCUMENTS_DIR, "Forensic_Reports")

PERIODIC_DIR = os.path.join(REPORT_ROOT_DIR, "json")
MANUAL_DIR = os.path.join(REPORT_ROOT_DIR, "manual-scans")

# Standard Linux system logs to check for periodic background scanning
SYSTEM_LOGS = [
    "/var/log/auth.log",   # Debian/Ubuntu auth logs
    "/var/log/secure",     # RHEL/CentOS auth logs
    "/var/log/syslog",     # General Linux system logs
    "sample.log"           # Fallback for testing
]

# Initialize Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Helper Functions ──

def get_active_system_log():
    """Finds the first available system log file for periodic scanning."""
    for log_path in SYSTEM_LOGS:
        if os.path.isfile(log_path) and os.access(log_path, os.R_OK):
            return log_path
    return None

def _file_metadata(filepath: str) -> dict:
    stats = os.stat(filepath)
    return {
        "filename": os.path.basename(filepath),
        "path": os.path.abspath(filepath),
        "size_bytes": stats.st_size,
        "modified_at": datetime.fromtimestamp(stats.st_mtime).isoformat(),
    }

def _safe_json(value):
    """Recursively makes Python objects JSON serializable."""
    if isinstance(value, dict):
        return {key: _safe_json(item) for key, item in value.items()}
    if isinstance(value, list) or isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, set):
        return sorted(_safe_json(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value

def analyze_log_file(log_path: str, threshold_seconds: float, original_filename: str = None) -> dict:
    """Core wrapper around your log.py engine."""
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    try:
        # Calls the scan_log function imported from your log.py
        result = scan_log(log_path, threshold_seconds)
        
        # Display the log.py terminal output in the console running the Flask server
        display_name = original_filename if original_filename else log_path
        report_terminal(result, display_name)
        
        # Force terminal to output immediately (prevents buffering issues in Flask)
        sys.stdout.flush()
    except SystemExit as exc:
        raise RuntimeError(f"Log analysis failed for {log_path}") from exc
        
    result["file_info"] = _file_metadata(log_path)
    
    # If manual scan, replace temp filename with the actual uploaded filename
    if original_filename:
        result["file_info"]["filename"] = original_filename

    result["risk_score"] = _risk_score(result.get("gaps", []), result.get("threats", []))
    result["threshold_seconds"] = threshold_seconds
    result["analysis_generated_at"] = datetime.now().isoformat()
    return result

def save_periodic_report(report_data: dict) -> dict:
    """Saves the report exactly matching log.py's hierarchical format."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    ts_str = datetime.now().strftime("%H%M%S")
    
    date_dir = os.path.join(PERIODIC_DIR, date_str)
    os.makedirs(date_dir, exist_ok=True)

    # Find the highest existing 'n' prefix to increment
    existing_files = os.listdir(date_dir)
    highest_n = 0
    for filename in existing_files:
        match = re.match(r"^(\d+)_", filename)
        if match:
            highest_n = max(highest_n, int(match.group(1)))
            
    n = highest_n + 1
    final_filename = f"{n}_forensic_data_{ts_str}.json"
    final_filepath = os.path.join(date_dir, final_filename)

    with open(final_filepath, "w", encoding="utf-8") as f:
        json.dump(_safe_json(report_data), f, indent=2)
        
    logger.info(f"Periodic report saved to: {final_filepath}")
    report_data["archive_path"] = final_filepath
    return report_data

def cleanup_manual_scans():
    """Deletes temporary manual scans older than 24 hours."""
    if not os.path.exists(MANUAL_DIR):
        return
    now = time.time()
    for filename in os.listdir(MANUAL_DIR):
        filepath = os.path.join(MANUAL_DIR, filename)
        if os.path.isfile(filepath):
            # If older than 24 hours (86400 seconds), delete it
            if now - os.stat(filepath).st_mtime > 86400:
                os.remove(filepath)


def _iter_report_files(root_dir: str):
    """Yield JSON report files under a root directory."""
    if not os.path.exists(root_dir):
        return
    for current_root, _, files in os.walk(root_dir):
        for filename in files:
            if filename.endswith(".json"):
                yield os.path.join(current_root, filename)


def _latest_report_path() -> Optional[str]:
    """Find the newest report from periodic and manual scan outputs."""
    candidates = []
    candidates.extend(_iter_report_files(PERIODIC_DIR) or [])
    candidates.extend(_iter_report_files(MANUAL_DIR) or [])
    if not candidates:
        return None
    return max(candidates, key=lambda path: os.path.getmtime(path))


def _build_calendar_payload() -> list:
    """Return periodic report files grouped by date for frontend calendar."""
    rows = []
    if not os.path.exists(PERIODIC_DIR):
        return rows

    for date_folder in sorted(os.listdir(PERIODIC_DIR), reverse=True):
        date_path = os.path.join(PERIODIC_DIR, date_folder)
        if not os.path.isdir(date_path):
            continue

        files = []
        for filename in sorted(os.listdir(date_path), reverse=True):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(date_path, filename)
            metadata = _file_metadata(filepath)
            metadata["extension"] = os.path.splitext(filename)[1].lstrip(".").lower()
            files.append(metadata)

        if files:
            rows.append({"date": date_folder, "files": files})

    return rows


def _resolve_periodic_report_path(filename: str, date: Optional[str] = None) -> str:
    """Resolve a periodic report path by date+filename or by filename lookup."""
    safe_filename = os.path.basename(filename)

    if date:
        safe_date = os.path.basename(date)
        candidate = os.path.join(PERIODIC_DIR, safe_date, safe_filename)
        if os.path.exists(candidate):
            return candidate
        raise FileNotFoundError(f"Report not found for {safe_date}/{safe_filename}")

    matches = []
    for path in _iter_report_files(PERIODIC_DIR) or []:
        if os.path.basename(path) == safe_filename:
            matches.append(path)

    if not matches:
        raise FileNotFoundError(f"Report not found for filename: {safe_filename}")

    return max(matches, key=lambda path: os.path.getmtime(path))

# ── Background Thread (24/7 Periodic Scanner) ──

def continuous_monitor():
    """Background thread that triggers system log scans every hour."""
    while True:
        target_log = get_active_system_log()
        if target_log:
            logger.info(f"--- Starting Periodic Scan on {target_log} ---")
            try:
                report_data = analyze_log_file(target_log, DEFAULT_THRESHOLD)
                report_data["scan_type"] = "periodic"
                
                # Save structured history
                report_data = save_periodic_report(report_data)
                
                # Emit to live dashboard via WebSockets
                socketio.emit('new_forensic_data', _safe_json(report_data))
                cleanup_manual_scans() # Housekeeping
                
            except Exception as e:
                logger.error(f"Periodic scan error: {e}")
                socketio.emit('scan_error', {"error": str(e), "target": target_log})
        else:
            logger.warning("No readable system logs found for periodic scan.")

        time.sleep(SCAN_INTERVAL)


# ── API Endpoints ──

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "running",
        "framework": "Flask",
        "active_system_log": get_active_system_log(),
        "report_root": REPORT_ROOT_DIR
    })


@app.route("/", methods=["GET"])
def index():
    """Human-friendly root route for quick browser checks."""
    return jsonify({
        "service": "Forensic Backend",
        "status": "running",
        "message": "Backend is up. Use the API endpoints below.",
        "endpoints": {
            "health": "/api/health",
            "latest_report": "/api/latest-report",
            "manual_analyze_post": "/api/analyze",
            "manual_analyze_post_new": "/api/analyze/manual",
            "calendar": "/api/local-log-calendar",
            "analyze_local_post": "/api/analyze-local",
            "periodic_reports": "/api/reports"
        }
    })


@app.route("/health", methods=["GET"])
def health_check_legacy():
    """Legacy health endpoint retained for frontend compatibility."""
    return health_check()


@app.route("/api/latest-report", methods=["GET"])
def latest_report():
    """Return the newest available report for dashboard bootstrap."""
    report_path = _latest_report_path()
    if not report_path:
        return jsonify({"error": "No reports available yet."}), 404

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return jsonify(_safe_json(payload))
    except Exception as exc:
        logger.exception("Failed to load latest report")
        return jsonify({"error": f"Failed to read latest report: {str(exc)}"}), 500

# 1. MANUAL SCAN ENDPOINT
@app.route("/api/analyze/manual", methods=["POST"])
def manual_scan():
    """Receives file from frontend, scans it, and stores temporarily."""
    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "Please upload a log file."}), 400

    threshold = float(request.form.get("threshold", DEFAULT_THRESHOLD))
    suffix = os.path.splitext(uploaded_file.filename)[1] or ".log"
    
    print(f"\n{'='*60}\n🚀 MANUAL SCAN TRIGGERED: {uploaded_file.filename}\n{'='*60}")
    sys.stdout.flush()
    
    # Save upload to secure temp file
    temp_fd, temp_path = tempfile.mkstemp(prefix="upload_", suffix=suffix)
    os.close(temp_fd)

    try:
        uploaded_file.save(temp_path)
        # Pass the real filename so it displays correctly in the terminal
        report_data = analyze_log_file(temp_path, threshold, original_filename=uploaded_file.filename)
        report_data["scan_type"] = "manual"
        
        # Save temporarily in manual-scans folder
        os.makedirs(MANUAL_DIR, exist_ok=True)
        temp_filename = f"manual_{int(time.time())}_{uploaded_file.filename}.json"
        temp_save_path = os.path.join(MANUAL_DIR, temp_filename)
        
        with open(temp_save_path, "w", encoding="utf-8") as f:
            json.dump(_safe_json(report_data), f, indent=2)
            
        report_data["archive_path"] = temp_save_path
        return jsonify(_safe_json(report_data))
        
    except Exception as exc:
        logger.exception("Manual analysis failed")
        return jsonify({"error": str(exc)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/api/analyze", methods=["POST"])
def manual_scan_legacy():
    """Legacy endpoint retained for existing frontend integration."""
    return manual_scan()


@app.route("/api/local-log-calendar", methods=["GET"])
def local_log_calendar_legacy():
    """Legacy calendar endpoint mapping to periodic archived reports."""
    return jsonify({"dates": _build_calendar_payload()})


@app.route("/api/analyze-local", methods=["POST"])
def analyze_local_legacy():
    """Legacy local analysis endpoint: load archived periodic report JSON."""
    payload = request.get_json(silent=True) or {}
    filename = payload.get("filename", "")
    date = payload.get("date")

    if not filename:
        return jsonify({"error": "Filename is required."}), 400

    try:
        report_path = _resolve_periodic_report_path(filename, date)
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
        return jsonify(_safe_json(report_data))
    except Exception as exc:
        logger.exception("Legacy analyze-local failed")
        return jsonify({"error": str(exc)}), 400

# 2. PERIODIC SCANS LIST ENDPOINT
@app.route("/api/reports", methods=["GET"])
def list_periodic_reports():
    """Returns a nested list of all periodic reports grouped by date."""
    reports = []
    if not os.path.exists(PERIODIC_DIR):
        return jsonify([])

    # Iterate through YYYY-MM-DD folders
    for date_folder in sorted(os.listdir(PERIODIC_DIR), reverse=True):
        date_path = os.path.join(PERIODIC_DIR, date_folder)
        if os.path.isdir(date_path):
            folder_reports = []
            # Iterate through files in the folder
            for filename in sorted(os.listdir(date_path), reverse=True):
                if filename.endswith(".json"):
                    folder_reports.append({
                        "filename": filename,
                        "url": f"/api/reports/{date_folder}/{filename}"
                    })
            if folder_reports:
                reports.append({
                    "date": date_folder,
                    "files": folder_reports
                })
                
    return jsonify(reports)

# 3. GET SPECIFIC PERIODIC REPORT
@app.route("/api/reports/<date>/<filename>", methods=["GET"])
def get_specific_report(date, filename):
    """Fetches a specific JSON report clicked on from the frontend list."""
    # Sanitize inputs to prevent directory traversal
    safe_date = os.path.basename(date)
    safe_filename = os.path.basename(filename)
    
    filepath = os.path.join(PERIODIC_DIR, safe_date, safe_filename)
    
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"error": f"Failed to read file: {str(e)}"}), 500
            
    return jsonify({"error": "Report not found"}), 404

@socketio.on('connect')
def handle_connect():
    logger.info("React client connected to WebSocket.")
    report_path = _latest_report_path()
    if not report_path:
        return
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        emit('initial_data', _safe_json(payload))
    except Exception:
        logger.exception("Failed to emit initial_data to client")

if __name__ == "__main__":
    # Check if a logfile was passed as a command-line argument
    if len(sys.argv) > 1:
        cli_log_file = sys.argv[1]
        if os.path.exists(cli_log_file):
            print(f"\n[+] CLI Argument Detected. Running initial analysis on: {cli_log_file}")
            # Insert at the top of the SYSTEM_LOGS so the periodic scanner uses it
            SYSTEM_LOGS.insert(0, cli_log_file)
            try:
                # Trigger an initial scan immediately to show terminal output
                initial_report = analyze_log_file(cli_log_file, DEFAULT_THRESHOLD)
                initial_report["scan_type"] = "periodic"
                save_periodic_report(initial_report)
                print("\n[+] Analysis complete. Starting Flask Server now...\n")
            except Exception as e:
                logger.error(f"Initial scan failed: {e}")
        else:
            logger.error(f"Provided log file not found: {cli_log_file}")
            sys.exit(1)

    # Start the continuous 24/7 monitoring background thread
    monitor_thread = threading.Thread(target=continuous_monitor, daemon=True)
    monitor_thread.start()
    
    # Start server
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
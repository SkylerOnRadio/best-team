import time
import json
import os
import logging
import threading
import tempfile
from datetime import datetime
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from log_checker_5 import scan_log, _risk_score

# --- CONFIGURATION ---
# Path to the log checker script used by the dashboard
CHECKER_SCRIPT_PATH = "./log.py"
# The log file to monitor
TARGET_LOG_FILE = "sample.log"
# Temporary location for the generated report
TEMP_REPORT_JSON = "latest_forensic_report.json"
# Scan interval (120 seconds = 2 minutes)
SCAN_INTERVAL = 3600
DEFAULT_THRESHOLD = 300.0
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_LOCK = threading.Lock()

# Initialize Logging for Server
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

def _resolve_path(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)

def _file_metadata(filepath: str) -> dict:
    stats = os.stat(filepath)
    return {
        "filename": os.path.basename(filepath),
        "path": os.path.abspath(filepath),
        "size_bytes": stats.st_size,
        "modified_at": datetime.fromtimestamp(stats.st_mtime).isoformat(),
        "extension": os.path.splitext(filepath)[1],
    }

def _safe_json(value):
    if isinstance(value, dict):
        return {key: _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, set):
        return sorted(_safe_json(item) for item in value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value

def _write_cache(payload: dict) -> None:
    with REPORT_LOCK:
        with open(_resolve_path(TEMP_REPORT_JSON), "w", encoding="utf-8") as handle:
            json.dump(_safe_json(payload), handle, indent=2)

def analyze_log_file(log_path: str, threshold_seconds: float) -> dict:
    resolved_path = _resolve_path(log_path)
    if not os.path.isfile(resolved_path):
        raise FileNotFoundError(f"Log file not found: {resolved_path}")

    try:
        result = scan_log(resolved_path, threshold_seconds)
    except SystemExit as exc:
        raise RuntimeError(f"Log analysis failed for {resolved_path}") from exc
    result["file_info"] = _file_metadata(resolved_path)
    result["risk_score"] = _risk_score(result.get("gaps", []), result.get("threats", []))
    result["threshold_seconds"] = threshold_seconds
    result["analysis_source"] = os.path.abspath(resolved_path)
    result["analysis_generated_at"] = datetime.now().isoformat()
    return result

def run_forensic_scan():
    """
    Executes the evidence_protector.py script.
    Displays results in terminal and generates JSON for the frontend.
    """
    try:
        logger.info(f"--- Starting Scheduled Forensic Scan on {TARGET_LOG_FILE} ---")

        report_data = analyze_log_file(TARGET_LOG_FILE, DEFAULT_THRESHOLD)
        _write_cache(report_data)
        return report_data

    except Exception as e:
        logger.error(f"Execution error: {e}")
        return {"error": str(e)}

@app.route("/api/health", methods=["GET"])
def api_health_check():
    return jsonify({
        "status": "running",
        "framework": "Flask",
        "checker_path": CHECKER_SCRIPT_PATH,
        "target": TARGET_LOG_FILE,
    })

@app.route("/api/latest-report", methods=["GET"])
def api_latest_report():
    cache_path = _resolve_path(TEMP_REPORT_JSON)
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as handle:
            return jsonify(json.load(handle))

    try:
        report_data = analyze_log_file(TARGET_LOG_FILE, DEFAULT_THRESHOLD)
        _write_cache(report_data)
        return jsonify(_safe_json(report_data))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 404

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        return jsonify({"error": "Please upload a log file."}), 400

    threshold_value = request.form.get("threshold", request.args.get("threshold", DEFAULT_THRESHOLD))
    try:
        threshold_seconds = float(threshold_value)
    except (TypeError, ValueError):
        return jsonify({"error": "Threshold must be a number."}), 400

    suffix = os.path.splitext(uploaded_file.filename)[1] or ".log"
    temp_fd, temp_path = tempfile.mkstemp(prefix="forensic_upload_", suffix=suffix, dir=BASE_DIR)
    os.close(temp_fd)

    try:
        uploaded_file.save(temp_path)
        report_data = analyze_log_file(temp_path, threshold_seconds)
        return jsonify(_safe_json(report_data))
    except Exception as exc:
        logger.exception("Upload analysis failed")
        return jsonify({"error": str(exc)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def continuous_monitor():
    """Background thread that triggers the scan every 2 minutes."""
    while True:
        report_data = run_forensic_scan()
        
        # Emit data via SocketIO to all connected React clients
        if "error" not in report_data:
            logger.info("Scan complete. Broadcasting results to React frontend via SocketIO.")
            socketio.emit('new_forensic_data', report_data)
        else:
            socketio.emit('scan_error', report_data)

        time.sleep(SCAN_INTERVAL)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "running",
        "framework": "Flask",
        "checker_path": CHECKER_SCRIPT_PATH,
        "target": TARGET_LOG_FILE
    })

@socketio.on('connect')
def handle_connect():
    logger.info("React client connected to WebSocket.")
    # Send the latest known report immediately upon connection
    if os.path.exists(TEMP_REPORT_JSON):
        try:
            with open(TEMP_REPORT_JSON, "r") as f:
                last_data = json.load(f)
                emit('initial_data', last_data)
        except:
            pass

if __name__ == "__main__":
    # Start the monitoring loop in a background thread
    monitor_thread = threading.Thread(target=continuous_monitor, daemon=True)
    monitor_thread.start()
    
    # Start the Flask-SocketIO server
    # Defaulting to port 5000 (Flask standard)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
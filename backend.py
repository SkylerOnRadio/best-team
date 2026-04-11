import time
import json
import subprocess
import os
import logging
import threading
from datetime import datetime
from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# --- CONFIGURATION ---
# Path to your updated log checker script
CHECKER_SCRIPT_PATH = "./log_checker_2.py" 
# The log file to monitor
TARGET_LOG_FILE = "sample.log"
# Temporary location for the generated report
TEMP_REPORT_JSON = "latest_forensic_report.json"
# Scan interval (120 seconds = 2 minutes)
SCAN_INTERVAL = 120

# Initialize Logging for Server
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

def run_forensic_scan():
    """
    Executes the evidence_protector.py script.
    Displays results in terminal and generates JSON for the frontend.
    """
    try:
        # We run the command twice or capture and print? 
        # For a clean terminal experience, we run it to show terminal output,
        # then we run it to get the JSON file.
        
        logger.info(f"--- Starting Scheduled Forensic Scan on {TARGET_LOG_FILE} ---")
        
        # 1. Run for Terminal Display (Visual feedback on server)
        subprocess.run(["python3", CHECKER_SCRIPT_PATH, TARGET_LOG_FILE, "--format", "terminal"])

        # 2. Run for JSON Generation (Data for React)
        cmd_json = [
            "python3", 
            CHECKER_SCRIPT_PATH, 
            TARGET_LOG_FILE, 
            "--format", "json", 
            "--out", TEMP_REPORT_JSON,
            "--quiet" # Keep JSON generation silent in terminal
        ]
        subprocess.run(cmd_json, capture_output=True, text=True)

        if os.path.exists(TEMP_REPORT_JSON):
            with open(TEMP_REPORT_JSON, "r") as f:
                data = json.load(f)
                data["server_timestamp"] = datetime.now().isoformat()
                return data
        
        return {"error": "Report file not generated"}

    except Exception as e:
        logger.error(f"Execution error: {e}")
        return {"error": str(e)}

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
import re
import os
import time
import sqlite3
import threading
from typing import List, Dict, Any
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# System configuration
LOG_FILE_PATH = "/var/log/nginx/error.log"
DB_FILE_PATH = "waf_logs.db"

app = FastAPI(title="WAF Dashboard API", version="1.0")

# Enable CORS to allow Web UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database initialization
def init_db():
    """Initializes the SQLite database table for storing WAF attack logs."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            status_code INTEGER,
            rule_id TEXT,
            anomaly_score INTEGER,
            attack_type TEXT,
            request_uri TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Log parser & Classifier
# Regex pattern to extract relevant metadata from Nginx error log lines
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[error\].*?'
    r'\[client (?P<client_ip>[\d\.]+)\].*?'
    r'\[id "(?P<rule_id>\d+)"\].*?'
    r'Total Score: (?P<score>\d+).*?'
    r'request: "(?P<request>[^"]+)"'
)

def classify_attack(rule_id_str: str, request_str: str) -> str:
    """
    Categorizes attack type accurately using OWASP CRS Rule ID ranges first,
    falling back to URI signature inspection if Rule ID is generic.
    """
    try:
        rule_id = int(rule_id_str)
    except (ValueError, TypeError):
        rule_id = 0

    # 1. Primary Mapping based on OWASP CRS Rule ID Ranges
    if 942000 <= rule_id <= 942999:
        return "SQL Injection (SQLi)"
    elif 941000 <= rule_id <= 941999:
        return "Cross-Site Scripting (XSS)"
    elif 930000 <= rule_id <= 930999:
        return "Path Traversal / LFI"
    elif 932000 <= rule_id <= 932999:
        return "Command Injection"
    elif 933000 <= rule_id <= 933999:
        return "PHP Code Injection"

    # 2. Fallback: URI Signature Check (If Rule ID is 949110 / Anomaly Evaluation)
    req_lower = request_str.lower()
    if any(k in req_lower for k in [";", "|", "`", "cat%20", "wget", "curl"]):
        return "Command Injection"
    elif any(k in req_lower for k in ["script", "alert", "%3cscript%3e"]):
        return "Cross-Site Scripting (XSS)"
    elif any(k in req_lower for k in ["select", "union", "1=1", "%27"]):
        return "SQL Injection (SQLi)"
    elif any(k in req_lower for k in ["..", "etc/passwd"]):
        return "Path Traversal / LFI"

    return "Other Malicious Request"

def insert_log_to_db(data: Dict[str, Any]):
    """Inserts a structured log record into the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, client_ip, status_code, rule_id, anomaly_score, attack_type, request_uri)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data["timestamp"],
            data["client_ip"],
            403,
            data["rule_id"],
            int(data["score"]),
            data["attack_type"],
            data["request"]
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Error]: {e}")

# Real-time log 
def follow_log_file():
    """Continuously monitors and reads new lines from the Nginx error log (tail -f behavior)."""
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[Warning] File {LOG_FILE_PATH} does not exist yet!")
        return

    file = open(LOG_FILE_PATH, "r")
    # Seek to the end of the file to process only newly generated log lines
    file.seek(0, os.SEEK_END)

    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)  # Wait briefly if no new log line is present
            continue

        match = LOG_PATTERN.search(line)
        if match:
            parsed_data = match.groupdict()
            parsed_data["attack_type"] = classify_attack(
    	    parsed_data["rule_id"], parsed_data["request"]
	)

            # Store extracted event into SQLite database
            insert_log_to_db(parsed_data)
            print(f"[WAF Alert Logged] {parsed_data['client_ip']} - {parsed_data['attack_type']}")

# Start the log tailer as a background thread alongside the FastAPI server
parser_thread = threading.Thread(target=follow_log_file, daemon=True)
parser_thread.start()

# API Endpoint
@app.get("/api/stats/overview")
def get_overview_stats():
    """Returns aggregated attack metrics for dashboard visualization."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()

    # Total count of blocked attack requests
    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total_blocked = cursor.fetchone()[0]

    # Top 5 attacker IP addresses
    cursor.execute("SELECT client_ip, COUNT(*) as count FROM attack_logs GROUP BY client_ip ORDER BY count DESC LIMIT 5")
    top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

    # Attack distribution by category
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type")
    attack_types = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]

    conn.close()
    return {
        "total_blocked": total_blocked,
        "top_ips": top_ips,
        "attack_types": attack_types
    }

@app.get("/api/logs/recent")
def get_recent_logs(limit: int = 10):
    """Retrieves the most recent security log entries."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, client_ip, attack_type, anomaly_score, request_uri FROM attack_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r[0],
            "timestamp": r[1],
            "client_ip": r[2],
            "attack_type": r[3],
            "anomaly_score": r[4],
            "request_uri": r[5]
        })
    return logs

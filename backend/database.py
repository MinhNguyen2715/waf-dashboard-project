import sqlite3
from typing import Dict, Any, List
from config import DB_FILE_PATH

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

def fetch_overview_stats() -> Dict[str, Any]:
    """Retrieves aggregated attack metrics for dashboard visualization."""
    conn = sqlite3.connect(DB_FILE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT client_ip, COUNT(*) as count FROM attack_logs GROUP BY client_ip ORDER BY count DESC LIMIT 5")
    top_ips = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type")
    attack_types = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]

    conn.close()
    return {
        "total_blocked": total_blocked,
        "top_ips": top_ips,
        "attack_types": attack_types
    }

def fetch_recent_logs(limit: int = 10) -> List[Dict[str, Any]]:
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


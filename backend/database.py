import sqlite3
from typing import Dict, Any, List
from config import DB_FILE_PATH

def get_db_connection():
    conn = sqlite3.connect(DB_FILE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
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

def insert_log_to_db(parsed_data):
    score = parsed_data.get("anomaly_score") or 5

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO attack_logs (
                timestamp, client_ip, rule_id, anomaly_score, attack_type, request_uri
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            parsed_data.get("timestamp"),
            parsed_data.get("client_ip"),
            parsed_data.get("rule_id"),
            score,
            parsed_data.get("attack_type"),
            parsed_data.get("request_uri")
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Error]: {e}")

def fetch_overview_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Total Blocked
    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total_blocked = cursor.fetchone()[0] or 0

    # 2. Top Attacker IP
    cursor.execute("SELECT client_ip, COUNT(*) as count FROM attack_logs GROUP BY client_ip ORDER BY count DESC LIMIT 1")
    top_ip_row = cursor.fetchone()
    top_attacker_ip = top_ip_row[0] if top_ip_row else "N/A"
    top_ip_count = top_ip_row[1] if top_ip_row else 0

    # 3. Most Frequent Attack
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type ORDER BY count DESC LIMIT 1")
    top_type_row = cursor.fetchone()
    most_frequent_attack = top_type_row[0] if top_type_row else "None"

    # 4. High Threat Count: Đếm các Request có Total Score dồn cao (>= 8)
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE anomaly_score >= 8")
    high_threat_count = cursor.fetchone()[0] or 0

    # 5. Distribution chart
    cursor.execute("SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type")
    attack_distribution = {row[0]: row[1] for row in cursor.fetchall()}

    conn.close()
    return {
        "total_blocked": total_blocked,
        "top_attacker_ip": top_attacker_ip,
        "top_ip_count": top_ip_count,
        "most_frequent_attack": most_frequent_attack,
        "high_threat_count": high_threat_count,
        "attack_distribution": attack_distribution
    }

def fetch_recent_logs(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, client_ip, attack_type, anomaly_score, request_uri, rule_id FROM attack_logs ORDER BY id DESC LIMIT ?", (limit,))
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
            "request_uri": r[5],
            "rule_id": r[6] if r[6] else "N/A"
        })
    return logs

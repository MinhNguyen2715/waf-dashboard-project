import os
import sqlite3
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "waf_logs.db")

def init_db():
    """Khởi tạo bảng waf_audit_logs và tự động nâng cấp schema nếu thiếu cột mới cho AI"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS waf_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT,
        timestamp TEXT,
        client_ip TEXT,
        host_ip TEXT,
        method TEXT,
        uri TEXT,
        user_agent TEXT,
        status_code INTEGER,
        anomaly_score INTEGER,
        attack_type TEXT,
        all_attack_types TEXT,
        matched_rules TEXT,
        raw_message TEXT,
        ai_attack_type TEXT DEFAULT 'N/A',
        final_action TEXT DEFAULT 'ALLOW',
        blocked_by TEXT DEFAULT 'None',
        latency_ms REAL DEFAULT 0.0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()

    # Danh sách các cột nâng cấp tự động cho CSDL cũ đã tồn tại trên đĩa
    columns_to_add = [
        ("all_attack_types", "TEXT"),
        ("ai_attack_type", "TEXT DEFAULT 'N/A'"),
        ("final_action", "TEXT DEFAULT 'ALLOW'"),
        ("blocked_by", "TEXT DEFAULT 'None'"),
        ("latency_ms", "REAL DEFAULT 0.0")
    ]

    for col_name, col_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE waf_audit_logs ADD COLUMN {col_name} {col_type}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Cột đã tồn tại sẵn

    conn.close()
    print(f"[+] Database initialized at: {DB_PATH}", flush=True)

def insert_log_to_db(log_data: Dict[str, Any]):
    """Chèn 1 bản ghi log đã parse kết hợp giữa ModSecurity và AI vào SQLite DB"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO waf_audit_logs (
            transaction_id, timestamp, client_ip, host_ip, method, uri,
            user_agent, status_code, anomaly_score, attack_type, all_attack_types,
            matched_rules, raw_message, ai_attack_type, final_action, blocked_by, latency_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_data.get("transaction_id"),
            log_data.get("timestamp"),
            log_data.get("client_ip"),
            log_data.get("host_ip"),
            log_data.get("method"),
            log_data.get("uri"),
            log_data.get("user_agent"),
            log_data.get("status_code"),
            log_data.get("anomaly_score", 0),
            log_data.get("attack_type", "000 - Normal"),
            log_data.get("all_attack_types", ""),
            log_data.get("matched_rules", ""),
            log_data.get("raw_message", ""),
            log_data.get("ai_attack_type", "000 - Normal"),
            log_data.get("final_action", "ALLOW"),
            log_data.get("blocked_by", "None"),
            log_data.get("latency_ms", 0.0)
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Database Error]: Không thể lưu log vào DB: {e}", flush=True)

def fetch_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Hàm lấy N bản ghi log mới nhất đầy đủ thông tin ModSec + AI phục vụ API routes/logs.py"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, transaction_id, timestamp, client_ip, host_ip, method, uri,
               user_agent, status_code, anomaly_score, attack_type, all_attack_types,
               matched_rules, raw_message, ai_attack_type, final_action, blocked_by,
               latency_ms, created_at
        FROM waf_audit_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def fetch_log_stats() -> Dict[str, Any]:
    """Hàm lấy thống kê phục vụ API routes/stats.py"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM waf_audit_logs")
    total_threats = cursor.fetchone()[0] or 0

    cursor.execute("""
        SELECT attack_type, COUNT(*)
        FROM waf_audit_logs
        GROUP BY attack_type
    """)
    breakdown = dict(cursor.fetchall())
    conn.close()

    return {
        "total_threats": total_threats,
        "breakdown": breakdown
    }

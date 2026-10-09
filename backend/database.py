import os
import sqlite3
from typing import Dict, Any, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "waf_logs.db")

def init_db():
    """Khởi tạo bảng waf_audit_logs và tự động nâng cấp schema nếu thiếu cột"""
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()

    # Tự động thêm cột all_attack_types nếu DB đã tồn tại từ trước mà chưa có cột này
    try:
        cursor.execute("ALTER TABLE waf_audit_logs ADD COLUMN all_attack_types TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Cột đã tồn tại sẵn

    conn.close()
    print(f"[+] Database initialized at: {DB_PATH}", flush=True)

def insert_log_to_db(log_data: Dict[str, Any]):
    """Chèn 1 bản ghi log đã parse từ JSON vào SQLite DB"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO waf_audit_logs (
            transaction_id, timestamp, client_ip, host_ip, method, uri,
            user_agent, status_code, anomaly_score, attack_type, all_attack_types, matched_rules, raw_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_data.get("transaction_id"),
            log_data.get("timestamp"),
            log_data.get("client_ip"),
            log_data.get("host_ip"),
            log_data.get("method"),
            log_data.get("uri"),
            log_data.get("user_agent"),
            log_data.get("status_code"),
            log_data.get("anomaly_score"),
            log_data.get("attack_type"),
            log_data.get("all_attack_types"),
            log_data.get("matched_rules"),
            log_data.get("raw_message")
        ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Database Error]: Không thể lưu log vào DB: {e}", flush=True)

def fetch_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Hàm lấy N bản ghi log mới nhất phục vụ API routes/logs.py"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, transaction_id, timestamp, client_ip, host_ip, method, uri,
               user_agent, status_code, anomaly_score, attack_type, all_attack_types, matched_rules,
               raw_message, created_at
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

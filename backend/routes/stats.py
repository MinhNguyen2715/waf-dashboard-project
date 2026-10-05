from fastapi import APIRouter
import sqlite3

router = APIRouter(prefix="/api/stats", tags=["Stats"])

DB_PATH = "waf_logs.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@router.get("/overview")
def get_overview_stats():
    conn = get_db()
    cursor = conn.cursor()

    # 1. Total Threats Blocked
    cursor.execute("SELECT COUNT(*) FROM attack_logs")
    total_blocked = cursor.fetchone()[0] or 0

    # 2. Top Attacker IP
    cursor.execute("""
        SELECT client_ip, COUNT(*) as count 
        FROM attack_logs 
        GROUP BY client_ip 
        ORDER BY count DESC LIMIT 1
    """)
    top_ip_row = cursor.fetchone()
    top_attacker_ip = top_ip_row["client_ip"] if top_ip_row else "N/A"
    top_ip_count = top_ip_row["count"] if top_ip_row else 0

    # 3. Most Frequent Attack Type
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM attack_logs 
        GROUP BY attack_type 
        ORDER BY count DESC LIMIT 1
    """)
    top_type_row = cursor.fetchone()
    most_frequent_attack = top_type_row["attack_type"] if top_type_row else "None"

    # 4. High Threat Level Count (Score >= 5 hoặc 8)
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE anomaly_score >= 8")
    high_threat_count = cursor.fetchone()[0] or 0

    # 5. Attack Distribution (Cho biểu đồ Donut Chart)
    cursor.execute("""
        SELECT attack_type, COUNT(*) as count 
        FROM attack_logs 
        GROUP BY attack_type
    """)
    distribution_rows = cursor.fetchall()
    attack_distribution = {row["attack_type"]: row["count"] for row in distribution_rows}

    conn.close()

    return {
        "total_blocked": total_blocked,
        "top_attacker_ip": top_attacker_ip,
        "top_ip_count": top_ip_count,
        "most_frequent_attack": most_frequent_attack,
        "high_threat_count": high_threat_count,
        "attack_distribution": attack_distribution
    }

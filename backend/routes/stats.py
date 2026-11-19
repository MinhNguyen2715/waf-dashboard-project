import os
import sqlite3
from fastapi import APIRouter

router = APIRouter(prefix="/api/stats", tags=["Stats"])

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "waf_logs.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@router.get("/overview")
def get_overview_stats():
    conn = get_db()
    cursor = conn.cursor()

    try:
        # 1. Total Threats Blocked
        cursor.execute("SELECT COUNT(*) FROM waf_audit_logs WHERE final_action = 'BLOCK' OR attack_type != '000 - Normal'")
        total_blocked = cursor.fetchone()[0] or 0

        # 2. Top Attacker IP
        cursor.execute("""
            SELECT client_ip, COUNT(*) as count
            FROM waf_audit_logs
            WHERE final_action = 'BLOCK' OR attack_type != '000 - Normal'
            GROUP BY client_ip
            ORDER BY count DESC LIMIT 1
        """)
        top_ip_row = cursor.fetchone()
        top_attacker_ip = top_ip_row["client_ip"] if top_ip_row else "N/A"
        top_ip_count = top_ip_row["count"] if top_ip_row else 0

        # 3. Most Frequent Attack Type
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM waf_audit_logs
            WHERE attack_type != '000 - Normal'
            GROUP BY attack_type
            ORDER BY count DESC LIMIT 1
        """)
        top_type_row = cursor.fetchone()
        most_frequent_attack = top_type_row["attack_type"] if top_type_row else "None"

        # 4. High Threat Level Count (Anomaly Score >= 5)
        cursor.execute("SELECT COUNT(*) FROM waf_audit_logs WHERE anomaly_score >= 5")
        high_threat_count = cursor.fetchone()[0] or 0

        # 5. Attack Distribution
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN LOWER(blocked_by) LIKE '%secbert%' OR LOWER(blocked_by) LIKE '%ai%' 
                    THEN ai_attack_type
                    ELSE attack_type
                END as main_type,
                COUNT(*) as count
            FROM waf_audit_logs
            WHERE final_action = 'BLOCK' 
               OR attack_type NOT IN ('Normal', 'None', '')
               OR ai_attack_type NOT IN ('Normal', 'Skipped (Fast-Path)', 'None', '')
            GROUP BY main_type
            HAVING main_type NOT IN ('Normal', 'Skipped (Fast-Path)', 'None', '')
        """)
        distribution_rows = cursor.fetchall()
        attack_distribution = {}
        for row in distribution_rows:
            raw_type = row["main_type"] or "Unknown"
            clean_type = raw_type.split("-")[-1].strip() if "-" in raw_type else raw_type.strip()
            attack_distribution[clean_type] = attack_distribution.get(clean_type, 0) + row["count"]

    except Exception as e:
        print(f"[Stats API Error]: {e}", flush=True)
        return {
            "total_blocked": 0,
            "top_attacker_ip": "N/A",
            "top_ip_count": 0,
            "most_frequent_attack": "None",
            "high_threat_count": 0,
            "attack_distribution": {}
        }
    finally:
        conn.close()

    return {
        "total_blocked": total_blocked,
        "top_attacker_ip": top_attacker_ip,
        "top_ip_count": top_ip_count,
        "most_frequent_attack": most_frequent_attack,
        "high_threat_count": high_threat_count,
        "attack_distribution": attack_distribution
    }


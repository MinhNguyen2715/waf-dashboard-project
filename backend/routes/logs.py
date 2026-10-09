from fastapi import APIRouter
from database import fetch_recent_logs

router = APIRouter(prefix="/api/logs", tags=["Logs"])

@router.get("/recent")
def get_recent_logs(limit: int = 50):
    logs = fetch_recent_logs(limit=limit)

    formatted_logs = []
    for item in logs:
        uri_val = item.get("uri") or "N/A"
        raw_msg = item.get("raw_message") or ""
        matched_rules_str = item.get("matched_rules") or ""
        rule_list = [r.strip() for r in matched_rules_str.split(",") if r.strip()] if matched_rules_str else []

        # Bóc tách danh sách tất cả các Attack Types phục vụ Modal
        all_types_raw = item.get("all_attack_types") or item.get("attack_type") or ""
        all_types_list = [t.strip() for t in all_types_raw.split(",") if t.strip()]

        formatted_logs.append({
            "id": item.get("id"),
            "transaction_id": item.get("transaction_id"),
            "timestamp": item.get("timestamp"),
            "client_ip": item.get("client_ip"),
            "host_ip": item.get("host_ip"),
            "method": item.get("method"),

            "uri": uri_val,
            "request_uri": uri_val,
            "payload": uri_val if not raw_msg else f"{uri_val} | {raw_msg}",

            # Cột cho Bảng chính (Main Type: "SQL Injection", "PHP Injection" hoặc "Combined / Mixed Attack")
            "attack_type": item.get("attack_type"),
            "main_rule_id": rule_list[0] if rule_list else "N/A",

            # Dành riêng cho Popup Modal (Chứa mảng tất cả các loại tấn công)
            "all_attack_types": all_types_list,

            # Cột cho Detailed Logs & Modal (Full List Rules)
            "rule_id": matched_rules_str if matched_rules_str else "N/A",
            "matched_rules": rule_list,

            "anomaly_score": item.get("anomaly_score"),
            "status_code": item.get("status_code"),
            "created_at": item.get("created_at")
        })
    return formatted_logs

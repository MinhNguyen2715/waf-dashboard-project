import json
import re
from typing import Dict, Any, Optional, Tuple, List

def map_rule_id_to_type(rule_id: str) -> Optional[str]:
    """Ánh xạ trực tiếp từ Rule ID sang loại tấn công tiêu chuẩn OWASP CRS"""
    if not rule_id:
        return None
    
    r_str = str(rule_id)
    if r_str.startswith("942"):
        return "SQL Injection"
    elif r_str.startswith("941"):
        return "Cross-Site Scripting (XSS)"
    elif r_str.startswith("930"):
        return "Path Traversal / LFI"
    elif r_str.startswith("932") or r_str.startswith("944"):
        return "Remote Code Execution (RCE)"
    elif r_str.startswith("933"):
        return "PHP Injection"
    elif r_str.startswith("913"):
        return "Security Scanner Detected"
    elif r_str.startswith("920") or r_str.startswith("921"):
        return "Protocol Violation"
    elif r_str.startswith("931"):
        return "Remote File Inclusion (RFI)"
    elif r_str.startswith("934"):
        return "Node.js Injection"
    return None

def parse_attack_types(rule_ids: List[str], tags: list, msg_text: str) -> Tuple[str, List[str]]:
    """Xác định loại tấn công chính và danh sách tất cả các loại tấn công"""
    detected_types = set()

    # 1. Tra cứu theo Rule ID
    for r_id in rule_ids:
        atype = map_rule_id_to_type(r_id)
        if atype:
            detected_types.add(atype)

    # 2. Tra cứu theo Tags / Message nếu chưa tìm thấy
    if not detected_types:
        tag_str = " ".join(tags).lower()
        msg_str = msg_text.lower()

        if "attack-sqli" in tag_str or "sqli" in msg_str or "sql" in msg_str:
            detected_types.add("SQL Injection")
        elif "attack-xss" in tag_str or "xss" in msg_str:
            detected_types.add("Cross-Site Scripting (XSS)")
        elif "attack-lfi" in tag_str or "attack-rfi" in tag_str or "traversal" in msg_str:
            detected_types.add("Path Traversal / LFI")
        elif "attack-rce" in tag_str or "command-execution" in msg_str or "attack-rce" in msg_str:
            detected_types.add("Remote Code Execution (RCE)")
        elif "attack-protocol" in tag_str:
            detected_types.add("Protocol Violation")

    all_types_list = sorted(list(detected_types)) if detected_types else ["Generic Attack / Anomaly"]

    # 3. Logic Hybrid
    if not detected_types:
        main_type = "Generic Attack / Anomaly"
    elif len(detected_types) == 1:
        main_type = all_types_list[0]
    else:
        main_type = "Combined / Mixed Attack"

    return main_type, all_types_list

def extract_total_score(messages: list) -> int:
    """Trích xuất tổng điểm Anomaly Score từ Rule 949110"""
    for msg in messages:
        msg_text = msg.get("message", "")
        if "Inbound Anomaly Score Exceeded" in msg_text:
            match = re.search(r"Total Score:\s*(\d+)", msg_text)
            if match:
                return int(match.group(1))
    return 0

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse từng dòng JSON đơn lẻ từ /var/log/modsec_audit.log"""
    if not line.strip():
        return None

    try:
        data = json.loads(line)
        tx = data.get("transaction", {})

        req = tx.get("request", {})
        resp = tx.get("response", {})
        messages = tx.get("messages", [])

        rule_ids = []
        all_tags = []
        main_attack_msg = ""

        for msg in messages:
            details = msg.get("details", {})
            rule_id = details.get("ruleId")
            if rule_id and rule_id != "949110":
                r_id_str = str(rule_id)
                if r_id_str not in rule_ids:
                    rule_ids.append(str(rule_id))

                all_tags.extend(details.get("tags", []))
                if not main_attack_msg:
                    main_attack_msg = msg.get("message", "")

        main_attack_type, all_attack_types = parse_attack_types(rule_ids, all_tags, main_attack_msg)
        anomaly_score = extract_total_score(messages)

        return {
            "transaction_id": tx.get("unique_id"),
            "timestamp": tx.get("time_stamp"),
            "client_ip": tx.get("client_ip"),
            "host_ip": tx.get("host_ip"),
            "method": req.get("method"),
            "uri": req.get("uri"),
            "user_agent": req.get("headers", {}).get("User-Agent", "N/A"),
            "status_code": resp.get("http_code"),
            "anomaly_score": anomaly_score,
            "attack_type": main_attack_type,
            "all_attack_types": ",".join(all_attack_types),
            "matched_rules": ",".join(rule_ids),
            "raw_message": main_attack_msg or "WAF Intervention"
        }
    except Exception as e:
        print(f"[LogParser Error]: {e}", flush=True)
        return None

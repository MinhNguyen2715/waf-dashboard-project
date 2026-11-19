import json
import re
from typing import Dict, Any, Optional, Tuple, List
import pandas as pd

def map_rule_id_to_type(rule_id: str) -> Optional[str]:
    if not rule_id:
        return None

    r_str = str(rule_id).strip()

    if r_str.startswith("942"):
        return "SQL Injection"
    elif r_str.startswith("941"):
        return "Cross-Site Scripting (XSS)"
    elif r_str.startswith("930"):
        return "Path Traversal / LFI"
    elif r_str.startswith("932"):
        return "Remote Code Execution (RCE)"
    elif r_str.startswith("944"):
        return "Java Deserialization / RCE"
    elif r_str.startswith("933"):
        return "PHP Injection"
    elif r_str.startswith("934"):
        return "Node.js Injection"
    elif r_str.startswith("931"):
        return "Remote File Inclusion (RFI)"
    elif r_str.startswith("913"):
        return "Security Scanner Detected"
    elif r_str.startswith("921"):
        return "Protocol Attack / HTTP Response Splitting"
    elif r_str.startswith("920") or r_str.startswith("911"):
        return "Protocol Violation"
    elif r_str.startswith("943"):
        return "Session Fixation"
    
    return None

def parse_attack_types(rule_ids: List[str], tags: list, msg_text: str) -> Tuple[str, List[str]]:
    detected_types = set()

    for r_id in rule_ids:
        atype = map_rule_id_to_type(r_id)
        if atype:
            detected_types.add(atype)

    if not detected_types:
        tag_str = " ".join(tags).lower()
        msg_str = msg_text.lower()

        if "attack-sqli" in tag_str or "sqli" in msg_str or "sql" in msg_str:
            detected_types.add("SQL Injection")
        elif "attack-xss" in tag_str or "xss" in msg_str:
            detected_types.add("Cross-Site Scripting (XSS)")
        elif "attack-lfi" in tag_str or "attack-rfi" in tag_str or "traversal" in msg_str:
            detected_types.add("Path Traversal / LFI")
        elif "attack-rce" in tag_str or "command-execution" in msg_str:
            detected_types.add("Remote Code Execution (RCE)")
        elif "attack-protocol" in tag_str:
            detected_types.add("Protocol Violation")

    all_types_list = sorted(list(detected_types)) if detected_types else ["Normal"]
    if not detected_types:
        main_type = "Normal"
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
    """Parse trọn vẹn 1 dòng JSON log: Vừa bóc tách thông tin ModSecurity, vừa đóng gói payload_text cho AI"""
    if not line.strip():
        return None

    try:
        data = json.loads(line)
        tx = data.get("transaction", {})
        req = tx.get("request", {})
        resp = tx.get("response", {})
        messages = tx.get("messages", [])
        headers = req.get("headers", {})

        # 1. Trích xuất 6 trường HTTP thô và đóng gói payload_text cho SecBERT AI
        request_http_method = str(req.get("method", "GET")) if req.get("method") else "GET"
        request_http_request = str(req.get("uri", "/")) if req.get("uri") else "/"
        request_user_agent = str(headers.get("User-Agent", "")) if headers.get("User-Agent") else ""
        request_cookie = str(headers.get("Cookie", "")) if headers.get("Cookie") else ""
        request_body = str(req.get("body", "")) if req.get("body") else ""
        request_content_type = str(headers.get("Content-Type", "")) if headers.get("Content-Type") else ""

        clean_body = request_body.replace("\r", " ").replace("\n", " ")

        payload_text = (
            'PATH: ' + request_http_request
            + ' | COOKIE: ' + request_cookie
            + ' | METHOD: ' + request_http_method
            + ' | UA: ' + request_user_agent
            + ' | BODY: ' + clean_body
            + ' | CTYPE: ' + request_content_type
        )

        # 2. Trích xuất thông tin ModSecurity Rules & Anomaly Score
        rule_ids = []
        all_tags = []
        main_attack_msg = ""

        for msg in messages:
            details = msg.get("details", {})
            rule_id = details.get("ruleId")
            if rule_id and str(rule_id) != "949110":
                r_id_str = str(rule_id)
                if r_id_str not in rule_ids:
                    rule_ids.append(r_id_str)

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
            "method": request_http_method,
            "uri": request_http_request,
            "user_agent": request_user_agent or "N/A",
            "cookie": request_cookie,
            "content_type": request_content_type,
            "body": clean_body,
            "payload_text": payload_text,
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

def parse_line_to_payload(line: str) -> Optional[str]:
    parsed = parse_line(line)
    return parsed.get("payload_text") if parsed else None

def get_payload_list(file_path: str) -> List[str]:
    payloads = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                payload = parse_line_to_payload(line)
                if payload:
                    payloads.append(payload)
    except FileNotFoundError:
        print(f"[ERROR]: Log file not found at {file_path}")
    return payloads

def get_payload_dataframe(file_path: str) -> pd.DataFrame:
    payloads = get_payload_list(file_path)
    return pd.DataFrame({'payload_text': payloads})

import re

# Regex trích xuất timestamp, client IP, rule ID và URI từ Nginx error.log
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?'
    r'\[client (?P<client_ip>[\d\.]+)\].*?'
    r'\[id "(?P<rule_id>\d+)"\].*?'
    r'request: "(?P<request>[^"]+)"',
    re.DOTALL
)

def parse_line(line: str):
    line = line.strip()
    if not line or "ModSecurity: Access denied" not in line:
        return None

    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    rule_id = data.get("rule_id", "0")
    request_str = data.get("request", "")

    # Trích xuất Anomaly Score
    score = 5
    score_match = re.search(r'Total Score:\s*(\d+)', line, re.IGNORECASE)
    if score_match:
        score = int(score_match.group(1))

    # Nếu rule là Rule tổng kết 949110, ta dự đoán qua payload trong request_str
    attack_type = classify_attack(rule_id, request_str, line)

    return {
        "timestamp": data.get("timestamp"),
        "client_ip": data.get("client_ip", "127.0.0.1"),
        "rule_id": rule_id,
        "request_uri": request_str,
        "attack_type": attack_type,
        "anomaly_score": score,
        "blocked": True
    }


def classify_attack(rule_id_str: str, request_str: str, full_line: str = "") -> str:
    """
    Phân loại chính xác đòn tấn công từ Nginx Error Log
    """
    try:
        rule_id = int(rule_id_str)
    except (ValueError, TypeError):
        rule_id = 0

    # Phân loại theo dải Rule ID OWASP CRS
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
    elif 944000 <= rule_id <= 944999:
        return "Java Code Injection"
    elif 913000 <= rule_id <= 913999:
        return "Scanner & Bot Probe"

    # Fallback phân loại chính xác dựa trên Payload Request khi bị Rule 949110
    content_to_check = (request_str + " " + full_line).lower()

    if any(k in content_to_check for k in ["union", "select", "1=1", "%20union%20"]):
        return "SQL Injection (SQLi)"
    elif any(k in content_to_check for k in ["script", "alert(", "xss"]):
        return "Cross-Site Scripting (XSS)"
    elif any(k in content_to_check for k in ["../", "..\\", "boot.ini"]):
        return "Path Traversal / LFI"
    elif "java.lang" in content_to_check:
        return "Java Code Injection"
    elif "phpinfo" in content_to_check:
        return "PHP Code Injection"
    elif any(k in content_to_check for k in ["cmd=", "cat%20", "/etc/passwd", ";id"]):
        return "Command Injection"

    return "Other Malicious Request"

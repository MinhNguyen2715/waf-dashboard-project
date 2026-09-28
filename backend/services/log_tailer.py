import os
import time
from config import LOG_FILE_PATH
from database import insert_log_to_db
from services.log_parser import LOG_PATTERN, classify_attack

def follow_log_file():
    """Continuously monitors and reads new lines from the Nginx error log (tail -f behavior)."""
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[Warning] File {LOG_FILE_PATH} does not exist yet!")
        return

    file = open(LOG_FILE_PATH, "r")
    file.seek(0, os.SEEK_END)

    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue

        match = LOG_PATTERN.search(line)
        if match:
            parsed_data = match.groupdict()
            
            score_val = parsed_data.get("score") or parsed_data.get("score_alt") or 5
            parsed_data["score"] = int(score_val)

            parsed_data["attack_type"] = classify_attack(
                parsed_data["rule_id"], parsed_data["request"]
            )

            insert_log_to_db(parsed_data)
            print(f"[WAF Alert Logged] IP: {parsed_data['client_ip']} | Rule: {parsed_data['rule_id']} | Type: {parsed_data['attack_type']}")

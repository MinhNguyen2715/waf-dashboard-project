import os
import time
from config import LOG_FILE_PATH
from database import insert_log_to_db
from services.log_parser import parse_line

def follow_log_file():
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[Warning] File {LOG_FILE_PATH} does not exist yet!")
        return

    try:
        file = open(LOG_FILE_PATH, "r", encoding="utf-8")
        file.seek(0, os.SEEK_END)
        print(f"[INFO] Started tailing log file: {LOG_FILE_PATH}")
    except Exception as e:
        print(f"[Error] Cannot open log file: {e}")
        return

    while True:
        try:
            # Xử lý khi chạy lệnh truncate -s 0
            current_pos = file.tell()
            if os.path.exists(LOG_FILE_PATH) and os.path.getsize(LOG_FILE_PATH) < current_pos:
                print("[INFO] Log file truncated! Re-opening...")
                file.close()
                file = open(LOG_FILE_PATH, "r", encoding="utf-8")
                continue

            line = file.readline()
            if not line:
                time.sleep(0.3)
                continue

            parsed_data = parse_line(line)
            if parsed_data:
                insert_log_to_db(parsed_data)
                print(f"[WAF Alert Logged] IP: {parsed_data['client_ip']} | Type: {parsed_data['attack_type']} | Score: {parsed_data['anomaly_score']}")

        except Exception as e:
            print(f"[Error in tailer] {e}")
            time.sleep(1)

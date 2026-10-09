import os
import time
from config import LOG_FILE_PATH
from database import insert_log_to_db
from services.log_parser import parse_line

def follow_log_file():
    # 1. Nếu file chưa tồn tại khi bật server, vòng lặp chờ cho tới khi Nginx tạo file
    while not os.path.exists(LOG_FILE_PATH):
        print(f"[Warning] File {LOG_FILE_PATH} does not exist yet. Waiting...")
        time.sleep(2)

    try:
        file = open(LOG_FILE_PATH, "r", encoding="utf-8")
        file.seek(0, os.SEEK_END)  # Bắt đầu đọc từ dòng log mới nhất
        print(f"[INFO] Started tailing log file: {LOG_FILE_PATH}")
    except Exception as e:
        print(f"[Error] Cannot open log file: {e}")
        return

    while True:
        try:
            # 2. Xử lý khi file bị xoay (Log Rotate) hoặc bị xóa/tạo lại
            if not os.path.exists(LOG_FILE_PATH):
                time.sleep(1)
                continue

            current_pos = file.tell()
            # Xử lý khi chạy lệnh truncate -s 0 hoặc file bị thu nhỏ kích thước
            if os.path.getsize(LOG_FILE_PATH) < current_pos:
                print("[INFO] Log file truncated/rotated! Re-opening...")
                file.close()
                file = open(LOG_FILE_PATH, "r", encoding="utf-8")
                continue

            line = file.readline()
            if not line:
                time.sleep(0.3)
                continue

            # 3. Parse và lưu vào DB
            parsed_data = parse_line(line)
            if parsed_data:
                insert_log_to_db(parsed_data)
                print(f"[WAF Alert Logged] IP: {parsed_data.get('client_ip')} | Type: {parsed_data.get('attack_type')} | Score: {parsed_data.get('anomaly_score')}", flush=True)

        except Exception as e:
            print(f"[Error in tailer] {e}", flush=True)
            time.sleep(1)

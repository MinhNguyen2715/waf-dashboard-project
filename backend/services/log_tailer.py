import os
import time
from config import LOG_FILE_PATH
from database import insert_log_to_db, init_db
from services.log_parser import parse_line

from model.secbert import secbert_engine as ai_engine

SEND_ALL_TO_AI = False

FAST_PATH_RULES = {
    '913100', '913110', '913120', '920100',  # 310 - Scanning for Vulnerable Software
    '930100', '930110', '930120'            # 126 - Path Traversal
}

def is_fast_path_matched(matched_rules_str: str) -> bool:
    if not matched_rules_str:
        return False
    rules = [r.strip() for r in matched_rules_str.split(",") if r.strip()]
    return any(r in FAST_PATH_RULES for r in rules)

def follow_log_file():
    init_db()

    while not os.path.exists(LOG_FILE_PATH):
        print(f"[Warning] File {LOG_FILE_PATH} does not exist yet. Waiting...", flush=True)
        time.sleep(2)

    try:
        file = open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore")
        file.seek(0, os.SEEK_END)
        print(f"[INFO] Started tailing log file: {LOG_FILE_PATH}", flush=True)
        print(f"[INFO] AI Engine Mode: {'FULL CHECK (100% AI)' if SEND_ALL_TO_AI else 'FAST-PATH ENABLED'}", flush=True)
    except Exception as e:
        print(f"[Error] Cannot open log file: {e}", flush=True)
        return

    while True:
        try:
            if not os.path.exists(LOG_FILE_PATH):
                time.sleep(1)
                continue

            current_pos = file.tell()

            if os.path.getsize(LOG_FILE_PATH) < current_pos:
                print("[INFO] Log file truncated/rotated! Re-opening...", flush=True)
                file.close()
                file = open(LOG_FILE_PATH, "r", encoding="utf-8", errors="ignore")
                continue

            line = file.readline()
            if not line:
                time.sleep(0.3)
                continue

            # 4. Parse thông tin ModSec & đóng gói payload_text cho AI
            parsed_data = parse_line(line)
            if not parsed_data:
                continue

            start_time = time.time()
            matched_rules = parsed_data.get("matched_rules", "")
            modsec_label = parsed_data.get("attack_type", "Normal")

            if not SEND_ALL_TO_AI and is_fast_path_matched(matched_rules):
                ai_label = "Skipped (Fast-Path)"
                final_action = "BLOCK"
                blocked_by = "ModSecurity (Fast-Path)"
            else:
                payload_text = parsed_data.get("payload_text", "")
                ai_label = ai_engine.predict(payload_text)

                is_modsec_clean = (modsec_label == "Normal")
                is_ai_clean = (ai_label == "Normal")

                if is_modsec_clean and is_ai_clean:
                    final_action = "ALLOW"
                    blocked_by = "None"
                else:
                    final_action = "BLOCK"
                    blocked_by = "SecBERT AI" if not is_ai_clean else "ModSecurity Rules"

            latency_ms = round((time.time() - start_time) * 1000, 2)

            parsed_data["ai_attack_type"] = ai_label
            parsed_data["final_action"] = final_action
            parsed_data["blocked_by"] = blocked_by
            parsed_data["latency_ms"] = latency_ms

            insert_log_to_db(parsed_data)

            print(
                f"[WAF Alert] IP: {parsed_data.get('client_ip')} "
                f"| ModSec: {modsec_label} "
                f"| AI: {ai_label} "
                f"| Action: {final_action} ({blocked_by}) "
                f"| Latency: {latency_ms}ms",
                flush=True
            )

        except Exception as e:
            print(f"[Error in tailer] {e}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    follow_log_file()

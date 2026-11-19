from model.log_parser import get_payload_list, LOG_FILE_PATH
from model.secbert import secbert_engine

def main():
    print(f"INFO: Fetching latest logs from {LOG_FILE_PATH}...")
    # Lấy 5 payload_text mới nhất từ log ModSecurity
    payloads = get_payload_list(LOG_FILE_PATH)
    latest_5 = payloads[-5:] if len(payloads) >= 5 else payloads

    print(f"\n=== SECBERT AI PREDICTION FOR LATEST {len(latest_5)} MODSEC LOGS ===")
    for i, payload in enumerate(latest_5, 1):
        pred_label = secbert_engine.predict(payload)
        print(f"\n[{i}] PAYLOAD: {payload[:110]}...")
        print(f"    🎯 PREDICT: {pred_label}")

if __name__ == "__main__":
    main()

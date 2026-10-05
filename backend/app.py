import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import init_db
from services.log_tailer import follow_log_file
from routes import stats, logs

# Initialize Database Schema
init_db()

app = FastAPI(title="WAF Dashboard API", version="1.0")

# Enable CORS for Web UI integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(stats.router)
app.include_router(logs.router)

# Hàm bọc để bắt lỗi nếu log tailer bị crash
def run_tailer_with_debug():
    print("[+] Log Tailer Thread starting now...", flush=True)
    try:
        follow_log_file()
    except Exception as e:
        print(f"[CRITICAL ERROR in Log Tailer]: {e}", flush=True)

@app.on_event("startup")
def startup_event():
    parser_thread = threading.Thread(target=run_tailer_with_debug, daemon=True)
    parser_thread.start()
    print("[+] Registered Startup Event: Log Tailer Thread Launched!", flush=True)

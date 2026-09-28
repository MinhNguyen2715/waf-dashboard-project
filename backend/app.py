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

# Start Background Log Tailer Thread
parser_thread = threading.Thread(target=follow_log_file, daemon=True)
parser_thread.start()

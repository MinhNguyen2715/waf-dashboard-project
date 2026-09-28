from fastapi import APIRouter
from database import fetch_recent_logs

router = APIRouter(prefix="/api/logs", tags=["Logs"])

@router.get("/recent")
def get_recent_logs(limit: int = 10):
    """Retrieves the most recent security log entries."""
    return fetch_recent_logs(limit)

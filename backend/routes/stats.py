from fastapi import APIRouter
from database import fetch_overview_stats

router = APIRouter(prefix="/api/stats", tags=["Stats"])

@router.get("/overview")
def get_overview_stats():
    """Returns aggregated attack metrics for dashboard visualization."""
    return fetch_overview_stats()


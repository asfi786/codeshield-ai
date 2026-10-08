"""Service health route."""

from datetime import datetime, timezone

from fastapi import APIRouter

from app.config import settings
from app.models.schemas import HealthResponse

router = APIRouter()


@router.get("", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return service status, version and current UTC timestamp."""
    return HealthResponse(
        status="ok",
        version=settings.version,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

"""Job status polling route."""

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.job_manager import job_manager
from app.models.schemas import JobStatusResponse

router = APIRouter()


@router.get("/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str) -> Any:
    """Return the current status of an analysis job, including its result."""
    job = job_manager.get_job(job_id)
    if job is None:
        return JSONResponse(status_code=404, content={"detail": "Job not found"})
    return JobStatusResponse(**job)

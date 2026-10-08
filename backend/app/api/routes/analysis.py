"""Analysis job submission route.

POST /api/v1/analyze validates the request, enforces a per-IP rate limit,
registers a background job and immediately returns HTTP 202 with the job
id. The heavy work runs in a fire-and-forget asyncio task that reports
progress into the shared :data:`job_manager`; clients poll
GET /api/v1/jobs/{job_id} for status and the final report.
"""

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.job_manager import job_manager
from app.core.pipeline import run_analysis
from app.core.rate_limit import analyze_limiter
from app.models.schemas import AnalyzeRequest, JobAcceptedResponse
from app.utils.helpers import parse_github_url

logger = logging.getLogger(__name__)

router = APIRouter()


def _client_ip(request: Request) -> str:
    """Extract the real client IP, respecting reverse-proxy headers."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


@router.post("", status_code=202, response_model=JobAcceptedResponse)
async def start_analysis(payload: AnalyzeRequest, request: Request) -> Any:
    """Accept a repository URL and launch its analysis in the background."""
    ip = _client_ip(request)
    if not analyze_limiter.allow(ip):
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded. Please wait a minute and try again."
            },
        )
    if parse_github_url(payload.repo_url) is None:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid GitHub repository URL."},
        )

    job_id = job_manager.create_job(
        payload.repo_url, payload.github_token, payload.deep_scan
    )

    async def _runner() -> None:
        await job_manager.set_progress(job_id, 1, "Queued")
        try:
            result = await run_analysis(
                job_id,
                payload.repo_url,
                payload.github_token,
                payload.deep_scan,
                progress_cb=lambda p, s: job_manager.set_progress(job_id, p, s),
            )
        except Exception as exc:
            message = str(exc).strip() or exc.__class__.__name__
            logger.warning("analysis job %s failed: %s", job_id, message)
            await job_manager.fail(job_id, message)
        else:
            await job_manager.finish(job_id, result)

    asyncio.create_task(_runner(), name=f"codeshield-analysis-{job_id}")
    return JobAcceptedResponse(job_id=job_id, status="queued")

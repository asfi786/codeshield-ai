"""Background job registry for asynchronous repository analyses.

Jobs are kept in memory and guarded by an ``asyncio.Lock``. A periodic
cleanup task drops jobs older than :data:`JOB_TTL_SECONDS` so the registry
cannot grow without bound. The module-level :data:`job_manager` singleton
is the single shared instance used by every router and the app lifespan.
"""

import asyncio
import logging
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)

#: How long a job (finished or abandoned) is retained, in seconds.
JOB_TTL_SECONDS = 3600
#: How often the cleanup task sweeps for expired jobs, in seconds.
CLEANUP_INTERVAL_SECONDS = 600

_QUEUED = "queued"
_RUNNING = "running"
_COMPLETE = "completed"
_FAILED = "failed"


class JobManager:
    """In-memory registry of analysis jobs, safe for asyncio concurrency."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._created_at: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task[None] | None = None

    def create_job(
        self, repo_url: str, github_token: str | None, deep_scan: bool
    ) -> str:
        """Register a new analysis job and return its id (uuid4 hex).

        The request parameters are captured by the background runner's
        closure; only TTL bookkeeping is stored here so the job dict
        matches :class:`JobStatusResponse` exactly.
        """
        job_id = uuid.uuid4().hex
        self._jobs[job_id] = {
            "job_id": job_id,
            "status": _QUEUED,
            "progress": 0,
            "stage": "Queued",
            "result": None,
            "error": None,
        }
        self._created_at[job_id] = time.monotonic()
        logger.info("job %s created (deep_scan=%s)", job_id, deep_scan)
        return job_id

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Return the job dict, or ``None`` if unknown or already expired."""
        return self._jobs.get(job_id)

    async def set_progress(self, job_id: str, progress: float, stage: str) -> None:
        """Update a job's progress (0-100) and human-readable stage."""
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["progress"] = max(0, min(100, int(progress)))
            job["stage"] = stage
            if job["status"] == _QUEUED:
                job["status"] = _RUNNING

    async def finish(self, job_id: str, result: dict[str, Any]) -> None:
        """Mark a job complete and attach its final report."""
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["status"] = _COMPLETE
            job["progress"] = 100
            job["stage"] = "Complete"
            job["result"] = result

    async def fail(self, job_id: str, error: str) -> None:
        """Mark a job failed with a human-readable error message."""
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["status"] = _FAILED
            job["stage"] = "Failed"
            job["error"] = error

    def start_cleanup_task(self) -> asyncio.Task[None]:
        """Start (or reuse) the background task that expires old jobs.

        Must be called from within a running event loop (e.g. the app
        lifespan handler).
        """
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(
                self._cleanup_loop(), name="codeshield-job-cleanup"
            )
        return self._cleanup_task

    async def _cleanup_loop(self) -> None:
        """Sleep forever, sweeping expired jobs every interval."""
        while True:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            try:
                await self._drop_expired()
            except Exception:
                logger.exception("job cleanup sweep failed")

    async def _drop_expired(self) -> None:
        """Remove jobs older than :data:`JOB_TTL_SECONDS`."""
        now = time.monotonic()
        async with self._lock:
            expired = [
                job_id
                for job_id, created in self._created_at.items()
                if now - created > JOB_TTL_SECONDS
            ]
            for job_id in expired:
                self._jobs.pop(job_id, None)
                self._created_at.pop(job_id, None)
        if expired:
            logger.info("expired %d analysis job(s)", len(expired))


#: Shared singleton — import this in routers and the app lifespan so every
#: component observes the same job registry.
job_manager = JobManager()

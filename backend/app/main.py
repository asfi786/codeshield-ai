"""CodeShield AI — FastAPI application entry point.

Builds the app via :func:`create_app`, mounts the ``/api/v1`` routers,
serves the Tailwind frontend from ``/``, and starts the job-registry
cleanup task through an async lifespan handler (the modern replacement
for the deprecated ``@app.on_event``).
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import analysis, github, health, jobs
from app.config import settings
from app.core.job_manager import job_manager

logging.basicConfig(level=logging.DEBUG if settings.debug else logging.INFO)
logger = logging.getLogger(__name__)

#: <project>/backend/app/main.py -> parents[2] == <project>; frontend/ lives there.
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start background maintenance on boot; nothing to tear down."""
    job_manager.start_cleanup_task()
    logger.info("CodeShield AI v%s started", settings.version)
    yield
    logger.info("CodeShield AI shutting down")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        # Browsers reject credentials with a wildcard origin.
        allow_credentials="*" not in settings.allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/v1/health", tags=["health"])
    app.include_router(github.router, prefix="/api/v1/github", tags=["github"])
    app.include_router(analysis.router, prefix="/api/v1/analyze", tags=["analysis"])
    app.include_router(jobs.router, prefix="/api/v1/jobs", tags=["jobs"])

    index_file = FRONTEND_DIR / "index.html"

    @app.get("/", include_in_schema=False)
    async def serve_index() -> FileResponse:
        """Serve the single-page frontend."""
        return FileResponse(index_file)

    for mount_path, subdir in (("/css", "css"), ("/js", "js"), ("/assets", "assets")):
        static_dir = FRONTEND_DIR / subdir
        if static_dir.is_dir():
            app.mount(mount_path, StaticFiles(directory=static_dir), name=subdir)
        else:
            logger.debug("static dir %s missing; skipping mount %s", static_dir, mount_path)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        log_level="debug" if settings.debug else "info",
    )

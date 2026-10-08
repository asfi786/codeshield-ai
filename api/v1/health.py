"""Vercel serverless function: GET /api/v1/health (native path routing)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.main import create_app  # noqa: E402

app = create_app()

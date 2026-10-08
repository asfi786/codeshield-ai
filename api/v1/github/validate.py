"""Vercel serverless function: GET /api/v1/github/validate (native path routing)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "backend"))

from app.main import create_app  # noqa: E402

app = create_app()

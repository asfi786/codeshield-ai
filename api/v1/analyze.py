"""Vercel serverless function: POST /api/v1/analyze.

Vercel maps this file to its native path, so the FastAPI app sees the true
request path (rewrites to a single catch-all function lose the original
path). The full app is mounted; only this route is reachable here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.main import create_app  # noqa: E402

app = create_app()

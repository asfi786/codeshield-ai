"""Vercel framework entrypoint for CodeShield AI.

Vercel's Python runtime detects the FastAPI app via this default-location
``server.py`` (top-level ``app``) and routes every request to it, so the
app behaves exactly as it does locally. ``ANALYZE_MODE=sync`` is set in
``vercel.json`` because serverless functions cannot run background jobs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from app.main import app  # noqa: E402  (re-exported for Vercel)

__all__ = ["app"]

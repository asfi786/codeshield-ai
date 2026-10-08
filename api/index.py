"""Vercel serverless entrypoint for CodeShield AI.

Vercel's Python runtime serves ``api/index.py`` as a serverless function and
uses the module-level ``app`` as the ASGI application. Every route — the
JSON API and the static frontend — is handled by the FastAPI app itself;
``vercel.json`` rewrites all traffic here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import create_app  # noqa: E402

app = create_app()

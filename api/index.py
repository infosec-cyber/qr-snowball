"""Vercel Python entrypoint.

Vercel's @vercel/python runtime serves an ASGI `app` exported from a file under
/api. We add ../backend to the path and re-export the FastAPI app. vercel.json
rewrites every /api/* request here; the PWA is served as static assets from
/public."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.main import app  # noqa: E402

__all__ = ["app"]

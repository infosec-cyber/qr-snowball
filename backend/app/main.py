"""Relay API — a zero-knowledge, QR-native contact network.

The app mounts the ciphertext routes under /api. In production (Vercel) the PWA
static files are served by the platform and only /api/* reaches this function;
for local dev we also serve the PWA from ../../public so a single `uvicorn`
process is the whole app (same origin, which WebAuthn requires)."""
import os

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .routes_webauthn import router as webauthn_router
from .routes_keys import router as keys_router
from .routes_tokens import router as tokens_router
from .routes_connections import router as connections_router
from .routes_groups import router as groups_router

app = FastAPI(title="Relay", docs_url="/api/docs", openapi_url="/api/openapi.json")

for r in (webauthn_router, keys_router, tokens_router, connections_router, groups_router):
    app.include_router(r)


@app.get("/api/health")
def health():
    return {"ok": True, "storage": "blob" if store.USE_BLOB else "local-fs"}


# ---- local-dev static serving (no-op on Vercel, which serves /public itself) ----
_PUBLIC = os.path.join(os.path.dirname(__file__), "..", "..", "public")

if os.path.isdir(_PUBLIC):
    _INDEX = os.path.join(_PUBLIC, "index.html")

    # Capability links resolve their secret in the #fragment client-side, so the
    # server just returns the app shell for these paths.
    @app.get("/c/{token_id}")
    def _spa_card(token_id: str):
        return FileResponse(_INDEX)

    @app.get("/g/{group_id}")
    def _spa_group(group_id: str):
        return FileResponse(_INDEX)

    app.mount("/", StaticFiles(directory=_PUBLIC, html=True), name="static")
else:
    @app.get("/")
    def _root():
        return JSONResponse({"service": "relay", "api": "/api"})

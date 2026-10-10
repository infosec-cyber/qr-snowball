"""Object-store abstraction — the zero-knowledge store, reworked for serverless.

Each "row" is a small JSON object at a deterministic path. In production we persist
to a **private** Vercel Blob store (reads/writes go through this function with the
store token; blobs are never world-readable). Locally — no cloud token — we fall
back to the filesystem so `uvicorn` runs with no account.

Either way the server only ever holds ciphertext + ids + public keys. It never
stores a plaintext profile field or a symmetric key.

Paths (all values are url-safe 128-bit ids or base64url credential ids — no slashes):
    users/<uid>.json
    creds/<credential_id>.json
    keybundles/<uid>.json
    tokens/<token_id>.json
    conn/out/<from>/<to>.json
    conn/in/<to>/<from>.json
    groups/<gid>/meta.json
    groups/<gid>/members/<uid>.json
"""
import os
import json
import glob
from typing import Any

# A static read-write token (either canonical name), or the OIDC pair Vercel
# injects when a Blob store is connected. We only switch to Blob when we actually
# have credentials — merely running on Vercel (VERCEL=1) is not enough.
_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN") or os.environ.get("VERCEL_BLOB_READ_WRITE_TOKEN")
_OIDC = bool(os.environ.get("VERCEL_OIDC_TOKEN") and os.environ.get("BLOB_STORE_ID"))
USE_BLOB = bool(_TOKEN) or _OIDC


def auth_mode() -> str:
    return "token" if _TOKEN else "oidc" if _OIDC else "none"

_LOCAL_DIR = os.environ.get(
    "RELAY_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data"),
)

if USE_BLOB:
    import vercel.blob as _blob
    from vercel.blob import BlobNotFoundError

    _ACCESS = "private"
    # Pass the static token when we have one; otherwise let the SDK use the
    # OIDC credentials Vercel injects.
    _TOK = {"token": _TOKEN} if _TOKEN else {}

    def get_json(path: str) -> dict[str, Any] | None:
        try:
            res = _blob.get(path, access=_ACCESS, use_cache=False, **_TOK)
        except BlobNotFoundError:
            return None
        return json.loads(res.content)

    def put_json(path: str, obj: dict[str, Any]) -> None:
        _blob.put(
            path,
            json.dumps(obj).encode(),
            access=_ACCESS,
            content_type="application/json",
            add_random_suffix=False,
            overwrite=True,
            cache_control_max_age=0,
            **_TOK,
        )

    def delete(path: str) -> None:
        try:
            _blob.delete(path, **_TOK)
        except BlobNotFoundError:
            pass

    def list_prefix(prefix: str) -> list[str]:
        out: list[str] = []
        cursor: str | None = None
        while True:
            res = _blob.list_objects(prefix=prefix, cursor=cursor, **_TOK)
            out.extend(b.pathname for b in res.blobs)
            if not res.has_more:
                break
            cursor = res.cursor
        return out

else:  # ---- local filesystem fallback (dev only) ----

    def _fs(path: str) -> str:
        return os.path.join(_LOCAL_DIR, path)

    def get_json(path: str) -> dict[str, Any] | None:
        try:
            with open(_fs(path), "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def put_json(path: str, obj: dict[str, Any]) -> None:
        full = _fs(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = full + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, full)

    def delete(path: str) -> None:
        try:
            os.remove(_fs(path))
        except FileNotFoundError:
            pass

    def list_prefix(prefix: str) -> list[str]:
        root = _LOCAL_DIR.rstrip("/") + "/"
        hits = glob.glob(_fs(prefix) + "**", recursive=True)
        return [h[len(root):] for h in hits if os.path.isfile(h)]

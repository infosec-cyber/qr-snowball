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

_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN")
# On Vercel the OIDC path sets VERCEL=1 and the SDK resolves credentials itself.
USE_BLOB = bool(_TOKEN) or bool(os.environ.get("VERCEL"))

_LOCAL_DIR = os.environ.get(
    "RELAY_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data"),
)

if USE_BLOB:
    import vercel.blob as _blob
    from vercel.blob import BlobNotFoundError

    _ACCESS = "private"

    def get_json(path: str) -> dict[str, Any] | None:
        try:
            res = _blob.get(path, access=_ACCESS, token=_TOKEN, use_cache=False)
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
            token=_TOKEN,
        )

    def delete(path: str) -> None:
        try:
            _blob.delete(path, token=_TOKEN)
        except BlobNotFoundError:
            pass

    def list_prefix(prefix: str) -> list[str]:
        out: list[str] = []
        cursor: str | None = None
        while True:
            res = _blob.list_objects(prefix=prefix, cursor=cursor, token=_TOKEN)
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

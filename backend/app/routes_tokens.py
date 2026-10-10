"""Share tokens — the thing a personal QR points at.

A token wraps the owner's public+connect ciphertext blob. The symmetric key that
decrypts it never touches this endpoint; it rides in the QR URL fragment. Reads
are unauthenticated (the capability is the token_id + the fragment key) but honour
revoke/expiry/use limits. Writes and rotation require the owner's session.

Note: with eventual-consistency object storage the use/revoke checks are
best-effort (two near-simultaneous scans may both succeed) — acceptable for the
capability model, where the real gate is the secret fragment key."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import store
from .deps import current_user
from .ids import new_id

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


def _expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    return datetime.now(timezone.utc) > datetime.fromisoformat(expires_at)


class TokenCreate(BaseModel):
    blob: str                       # base64(nonce||ciphertext) of public+connect tiers
    meta: str | None = None         # opaque client layout hints
    uses_left: int | None = None    # None = unlimited
    expires_at: str | None = None   # ISO8601, None = never


def _write_token(token_id: str, uid: str, body: TokenCreate) -> None:
    store.put_json(f"tokens/{token_id}.json", {
        "token_id": token_id, "user_id": uid, "blob": body.blob, "meta": body.meta,
        "revoked": False, "uses_left": body.uses_left, "expires_at": body.expires_at,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


@router.post("")
def create_token(body: TokenCreate, uid: str = Depends(current_user)):
    token_id = new_id()
    _write_token(token_id, uid, body)
    return {"token_id": token_id}


@router.get("/{token_id}")
def read_token(token_id: str):
    tok = store.get_json(f"tokens/{token_id}.json")
    if not tok or tok["revoked"] or _expired(tok["expires_at"]):
        raise HTTPException(status_code=404, detail="token not available")
    if tok["uses_left"] is not None:
        if tok["uses_left"] <= 0:
            raise HTTPException(status_code=404, detail="token exhausted")
        tok["uses_left"] -= 1
        store.put_json(f"tokens/{token_id}.json", tok)

    keys = store.get_json(f"keybundles/{tok['user_id']}.json") or {}
    return {
        "token_id": token_id,
        "owner": tok["user_id"],
        "blob": tok["blob"],
        "meta": tok["meta"],
        "owner_pub_x25519": keys.get("pub_x25519"),
        "owner_pub_ed25519": keys.get("pub_ed25519"),
    }


@router.post("/{token_id}/rotate")
def rotate_token(token_id: str, body: TokenCreate, uid: str = Depends(current_user)):
    """Revoke the old token (its QR stops working) and mint a fresh one."""
    tok = store.get_json(f"tokens/{token_id}.json")
    if not tok or tok["user_id"] != uid:
        raise HTTPException(status_code=404, detail="token not found")
    tok["revoked"] = True
    store.put_json(f"tokens/{token_id}.json", tok)

    new_token = new_id()
    _write_token(new_token, uid, body)
    return {"token_id": new_token}

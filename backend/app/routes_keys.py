"""E2E identity keys.

Public keys are stored in the clear (peers encrypt to them); the private-key
bundle only as opaque ciphertext wrapped by a PRF/passphrase key the server never
sees. `GET /keys/me` restores a new device; `GET /keys/{id}` hands a peer their
public keys so clients can seal boxes to them."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import store
from .deps import current_user

router = APIRouter(prefix="/api/keys", tags=["keys"])


class KeyBundle(BaseModel):
    pub_x25519: str
    pub_ed25519: str
    enc_bundle: str   # opaque ciphertext
    kdf: str          # 'prf' | 'argon2id(...)' — opaque to the server


@router.post("")
def store_keys(bundle: KeyBundle, uid: str = Depends(current_user)):
    store.put_json(f"keybundles/{uid}.json", {
        "user_id": uid,
        "pub_x25519": bundle.pub_x25519,
        "pub_ed25519": bundle.pub_ed25519,
        "enc_bundle": bundle.enc_bundle,
        "kdf": bundle.kdf,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"ok": True}


@router.get("/me")
def my_bundle(uid: str = Depends(current_user)):
    row = store.get_json(f"keybundles/{uid}.json")
    if not row:
        raise HTTPException(status_code=404, detail="no key bundle")
    return {k: row[k] for k in ("pub_x25519", "pub_ed25519", "enc_bundle", "kdf")}


@router.get("/{user_id}")
def public_keys(user_id: str, uid: str = Depends(current_user)):
    row = store.get_json(f"keybundles/{user_id}.json")
    if not row:
        raise HTTPException(status_code=404, detail="unknown user")
    return {"user_id": user_id, "pub_x25519": row["pub_x25519"], "pub_ed25519": row["pub_ed25519"]}

"""Groups — the snowball chain.

The group key K_G lives only in the group QR fragment. Each member uploads their
own blob encrypted under K_G; the server just accumulates ciphertext and hands back
the roster. Whoever holds the group QR can add themselves and re-share the same QR,
so the group grows hand-to-hand. (Static K_G — see architecture caveat on group
forward secrecy.)"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import store
from .deps import current_user
from .ids import new_id

router = APIRouter(prefix="/api/groups", tags=["groups"])


class GroupMemberBlob(BaseModel):
    blob: str   # member's profile ciphertext under K_G (opaque)


@router.post("")
def create_group(body: GroupMemberBlob, uid: str = Depends(current_user)):
    group_id = new_id()
    now = datetime.now(timezone.utc).isoformat()
    store.put_json(f"groups/{group_id}/meta.json", {"group_id": group_id, "created_by": uid, "created_at": now})
    store.put_json(f"groups/{group_id}/members/{uid}.json", {"user_id": uid, "blob": body.blob, "joined_at": now})
    return {"group_id": group_id}


@router.post("/{group_id}/members")
def join_group(group_id: str, body: GroupMemberBlob, uid: str = Depends(current_user)):
    if not store.get_json(f"groups/{group_id}/meta.json"):
        raise HTTPException(status_code=404, detail="unknown group")
    store.put_json(f"groups/{group_id}/members/{uid}.json", {
        "user_id": uid, "blob": body.blob,
        "joined_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"ok": True}


@router.get("/{group_id}")
def read_group(group_id: str, uid: str = Depends(current_user)):
    if not store.get_json(f"groups/{group_id}/meta.json"):
        raise HTTPException(status_code=404, detail="unknown group")
    members = [store.get_json(p) for p in store.list_prefix(f"groups/{group_id}/members/")]
    members = sorted((m for m in members if m), key=lambda m: m["joined_at"])
    return {"group_id": group_id, "members": members}

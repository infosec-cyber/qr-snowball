"""Connections — the edges of the graph.

When A scans B, A records edge A->B and ships a `sealed_payload`: a libsodium
sealed box encrypted to B's X25519 public key, carrying A's own connect blob + key.
Only B can open it, making the connection mutual. The server stores the sealed
bytes verbatim and never learns their contents.

Each edge is written twice — under conn/out/<from>/<to> and conn/in/<to>/<from> —
so each direction is a cheap prefix list."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import store
from .deps import current_user

router = APIRouter(prefix="/api/connections", tags=["connections"])


class ConnectionCreate(BaseModel):
    to_user: str
    sealed_payload: str   # sealed box to to_user's X25519 pubkey (opaque)


@router.post("")
def create_connection(body: ConnectionCreate, uid: str = Depends(current_user)):
    if body.to_user == uid:
        raise HTTPException(status_code=400, detail="cannot connect to yourself")
    if not store.get_json(f"users/{body.to_user}.json"):
        raise HTTPException(status_code=404, detail="unknown user")
    now = datetime.now(timezone.utc).isoformat()
    store.put_json(f"conn/out/{uid}/{body.to_user}.json", {"to_user": body.to_user, "created_at": now})
    store.put_json(f"conn/in/{body.to_user}/{uid}.json",
                   {"from_user": uid, "sealed_payload": body.sealed_payload, "created_at": now})
    return {"ok": True}


@router.get("")
def list_connections(uid: str = Depends(current_user)):
    """Edges touching me, both directions. Outgoing exposes who I scanned; incoming
    carries the sealed_payload only I can open."""
    outgoing = [store.get_json(p) for p in store.list_prefix(f"conn/out/{uid}/")]
    incoming = [store.get_json(p) for p in store.list_prefix(f"conn/in/{uid}/")]
    outgoing = sorted((o for o in outgoing if o), key=lambda r: r["created_at"], reverse=True)
    incoming = sorted((i for i in incoming if i), key=lambda r: r["created_at"], reverse=True)
    return {"outgoing": outgoing, "incoming": incoming}

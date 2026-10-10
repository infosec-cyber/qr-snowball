"""Passkey registration & login.

The WebAuthn challenge is carried between begin/complete in a short-lived signed
cookie (no server-side session store — serverless-friendly). On successful
registration we create the user object; on login we bump the signature counter.
The returned session cookie is what every authenticated route checks."""
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from . import webauthn_svc, sessions, store
from .ids import new_id

router = APIRouter(prefix="/api/webauthn", tags=["webauthn"])

CHALLENGE_COOKIE = "relay_challenge"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_challenge(resp: Response, payload: dict) -> None:
    resp.set_cookie(
        CHALLENGE_COOKIE, sessions.make_challenge(payload),
        max_age=sessions.CHALLENGE_MAX_AGE,
        httponly=True, samesite="strict", secure=True, path="/",
    )


def _set_session(resp: Response, user_id: str) -> None:
    resp.set_cookie(
        sessions.SESSION_COOKIE, sessions.make_session(user_id),
        max_age=sessions.SESSION_MAX_AGE,
        httponly=True, samesite="strict", secure=True, path="/",
    )


class CompletePayload(BaseModel):
    credential: dict


@router.post("/register/begin")
def register_begin(response: Response):
    # Allocate the user_id now so the authenticator binds a stable handle; the
    # user object is only written once registration completes.
    user_id = new_id()
    options, challenge = webauthn_svc.registration_options(user_id, user_name=user_id)
    _set_challenge(response, {"challenge": challenge, "user_id": user_id, "op": "register"})
    return options


@router.post("/register/complete")
def register_complete(payload: CompletePayload, request: Request, response: Response):
    ch = sessions.read_challenge(request.cookies.get(CHALLENGE_COOKIE))
    if not ch or ch.get("op") != "register":
        raise HTTPException(status_code=400, detail="no pending registration")

    result = webauthn_svc.verify_registration(payload.credential, ch["challenge"])
    user_id = ch["user_id"]

    store.put_json(f"users/{user_id}.json", {"user_id": user_id, "created_at": _now()})
    store.put_json(f"creds/{result['credential_id']}.json", {
        "credential_id": result["credential_id"],
        "user_id": user_id,
        "public_key": bytes_to_base64url(result["public_key"]),
        "sign_count": result["sign_count"],
    })

    response.delete_cookie(CHALLENGE_COOKIE, path="/")
    _set_session(response, user_id)
    return {"user_id": user_id}


@router.post("/login/begin")
def login_begin(response: Response):
    options, challenge = webauthn_svc.authentication_options()
    _set_challenge(response, {"challenge": challenge, "op": "login"})
    return options


@router.post("/login/complete")
def login_complete(payload: CompletePayload, request: Request, response: Response):
    ch = sessions.read_challenge(request.cookies.get(CHALLENGE_COOKIE))
    if not ch or ch.get("op") != "login":
        raise HTTPException(status_code=400, detail="no pending login")

    credential_id = webauthn_svc.credential_id_from(payload.credential)
    cred = store.get_json(f"creds/{credential_id}.json")
    if not cred:
        raise HTTPException(status_code=404, detail="unknown credential")

    result = webauthn_svc.verify_authentication(
        payload.credential, ch["challenge"],
        base64url_to_bytes(cred["public_key"]), cred["sign_count"],
    )
    cred["sign_count"] = result["new_sign_count"]
    store.put_json(f"creds/{credential_id}.json", cred)

    response.delete_cookie(CHALLENGE_COOKIE, path="/")
    _set_session(response, cred["user_id"])
    return {"user_id": cred["user_id"]}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(sessions.SESSION_COOKIE, path="/")
    return {"ok": True}

"""Passkey registration & login.

The WebAuthn challenge (and the RP id / origin it was minted for) is carried
between begin/complete in a short-lived signed cookie — no server-side session
store, serverless-friendly. RP id and origin are derived from the request Host so
the app works on localhost and any Vercel domain without env tuning. On success we
create the user / bump the signature counter and set the session cookie."""
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse

from . import webauthn_svc, sessions, store
from .ids import new_id

router = APIRouter(prefix="/api/webauthn", tags=["webauthn"])

CHALLENGE_COOKIE = "relay_challenge"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rp(request: Request) -> tuple[str, str]:
    """(rp_id, origin) from the (proxied) Host — what the browser actually used."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "localhost"
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    return host.split(":")[0], f"{proto}://{host}"


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
def register_begin(request: Request, response: Response):
    rp_id, origin = _rp(request)
    # Allocate the user_id now so the authenticator binds a stable handle; the
    # user object is only written once registration completes.
    user_id = new_id()
    options, challenge = webauthn_svc.registration_options(user_id, user_name=user_id, rp_id=rp_id)
    _set_challenge(response, {"challenge": challenge, "user_id": user_id,
                             "op": "register", "rp_id": rp_id, "origin": origin})
    return options


@router.post("/register/complete")
def register_complete(payload: CompletePayload, request: Request, response: Response):
    ch = sessions.read_challenge(request.cookies.get(CHALLENGE_COOKIE))
    if not ch or ch.get("op") != "register":
        raise HTTPException(status_code=400, detail="no pending registration")

    try:
        result = webauthn_svc.verify_registration(
            payload.credential, ch["challenge"], ch["rp_id"], ch["origin"])
    except InvalidRegistrationResponse as e:
        raise HTTPException(status_code=400, detail=f"registration failed: {e}")

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
def login_begin(request: Request, response: Response):
    rp_id, origin = _rp(request)
    options, challenge = webauthn_svc.authentication_options(rp_id=rp_id)
    _set_challenge(response, {"challenge": challenge, "op": "login", "rp_id": rp_id, "origin": origin})
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

    try:
        result = webauthn_svc.verify_authentication(
            payload.credential, ch["challenge"],
            base64url_to_bytes(cred["public_key"]), cred["sign_count"],
            ch["rp_id"], ch["origin"])
    except InvalidAuthenticationResponse as e:
        raise HTTPException(status_code=400, detail=f"login failed: {e}")

    cred["sign_count"] = result["new_sign_count"]
    store.put_json(f"creds/{credential_id}.json", cred)

    response.delete_cookie(CHALLENGE_COOKIE, path="/")
    _set_session(response, cred["user_id"])
    return {"user_id": cred["user_id"]}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(sessions.SESSION_COOKIE, path="/")
    return {"ok": True}

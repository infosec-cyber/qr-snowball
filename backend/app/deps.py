"""Request dependencies: resolve the session cookie to a user_id.

Auth here means "proved control of a passkey earlier". It gates writes and
reads of a user's *own* ciphertext; it never unlocks anyone else's plaintext,
which the server cannot decrypt regardless."""
from fastapi import Request, HTTPException

from . import sessions


def current_user(request: Request) -> str:
    uid = sessions.read_session(request.cookies.get(sessions.SESSION_COOKIE))
    if not uid:
        raise HTTPException(status_code=401, detail="authentication required")
    return uid


def optional_user(request: Request) -> str | None:
    return sessions.read_session(request.cookies.get(sessions.SESSION_COOKIE))

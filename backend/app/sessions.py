"""Stateless signed cookies for sessions and WebAuthn challenges.

The signing key is ephemeral per-process unless RELAY_SECRET is set — fine for a
dev/hackathon build; set RELAY_SECRET in production so sessions survive restarts."""
import os
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

_SECRET = os.environ.get("RELAY_SECRET") or secrets.token_hex(32)

_session = URLSafeTimedSerializer(_SECRET, salt="relay-session")
_challenge = URLSafeTimedSerializer(_SECRET, salt="relay-challenge")

SESSION_COOKIE = "relay_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days
CHALLENGE_MAX_AGE = 60 * 5           # 5 minutes


def make_session(user_id: str) -> str:
    return _session.dumps({"uid": user_id})


def read_session(cookie: str | None) -> str | None:
    if not cookie:
        return None
    try:
        data = _session.loads(cookie, max_age=SESSION_MAX_AGE)
        return data.get("uid")
    except (BadSignature, SignatureExpired):
        return None


def make_challenge(payload: dict) -> str:
    return _challenge.dumps(payload)


def read_challenge(cookie: str | None) -> dict | None:
    if not cookie:
        return None
    try:
        return _challenge.loads(cookie, max_age=CHALLENGE_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None

"""Unguessable identifiers. Everything the outside world references is 128-bit
random, URL-safe, and non-sequential — there is nothing to enumerate."""
import secrets


def new_id(prefix: str = "") -> str:
    # 16 bytes = 128 bits of entropy, url-safe base64 (no padding).
    token = secrets.token_urlsafe(16)
    return f"{prefix}{token}" if prefix else token

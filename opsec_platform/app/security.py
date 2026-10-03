"""
Password hashing + session tokens.
"""

from __future__ import annotations

import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from opsec_platform.app.config import get_settings

_BCRYPT_MAX_BYTES = 72
_MIN_JWT_SECRET_BYTES = 32


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        raise ValueError(f"Password too long ({_BCRYPT_MAX_BYTES}-byte bcrypt limit) — use a shorter passphrase.")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _require_jwt_secret() -> str:
    secret = get_settings().jwt_secret
    if not secret:
        raise RuntimeError(
            "PLATFORM_JWT_SECRET is not set. Sessions cannot be issued without a signing key."
        )
    if get_settings().cookie_secure and len(secret.encode("utf-8")) < _MIN_JWT_SECRET_BYTES:
        raise RuntimeError("PLATFORM_JWT_SECRET must contain at least 32 UTF-8 bytes in HTTPS deployments.")
    return secret


def create_session_token(user_id: str, session_id: str, email: str) -> tuple[str, datetime]:
    settings = get_settings()
    secret = _require_jwt_secret()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.session_ttl_minutes)
    payload = {
        "sub": user_id,
        "jti": session_id,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, secret, algorithm=settings.jwt_algorithm)
    return token, expires_at


class InvalidSessionToken(Exception):
    pass


def decode_session_token(token: str) -> dict:
    settings = get_settings()
    secret = _require_jwt_secret()
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise InvalidSessionToken("Session expired.")
    except jwt.InvalidTokenError:
        raise InvalidSessionToken("Invalid session token.")

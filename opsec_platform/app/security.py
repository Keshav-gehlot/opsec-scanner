"""
Password hashing + session tokens.

Password hashing uses the `bcrypt` library directly rather than passlib
— passlib is unmaintained and its bcrypt backend is broken against
bcrypt>=4.1's changed API (confirmed by actually running it: it throws
`AttributeError: module 'bcrypt' has no attribute '__about__'` on
import, then a spurious "password cannot be longer than 72 bytes" on
the very first hash call). No point building auth on a broken dependency.

Session tokens are JWS-signed JWTs (PyJWT, HS256) — this is the "JWS"
half of what was asked for. The token is stateless and self-verifying
(signature + expiry), but carries a `jti` claim referencing a Session
DB row, so a session can actually be revoked (logout) rather than just
relying on the client discarding a cookie that would otherwise still
verify as valid until it expires.
"""

from __future__ import annotations

import bcrypt
import jwt
from datetime import datetime, timedelta, timezone

from opsec_platform.app.config import get_settings

_BCRYPT_MAX_BYTES = 72  # bcrypt's own hard limit; enforce it explicitly rather than let it fail confusingly


def hash_password(password: str) -> str:
    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        raise ValueError(f"Password too long ({_BCRYPT_MAX_BYTES}-byte bcrypt limit) — use a shorter passphrase.")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        # Malformed/corrupt stored hash — treat as "doesn't match" rather
        # than raising, so a bad DB row can't crash the login endpoint.
        return False


def create_session_token(user_id: str, session_id: str, email: str) -> tuple[str, datetime]:
    """Returns (token, expires_at). expires_at is also embedded in the
    token itself, but returned separately so callers can store it on the
    Session row without re-decoding the token they just created."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise RuntimeError(
            "PLATFORM_JWT_SECRET is not set. Sessions cannot be issued without a signing key — "
            "see opsec_platform/.env.example."
        )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.session_ttl_minutes)
    payload = {
        "sub": user_id,
        "jti": session_id,
        "email": email,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_at


class InvalidSessionToken(Exception):
    pass


def decode_session_token(token: str) -> dict:
    """Verifies signature + expiry and returns the claims. Raises
    InvalidSessionToken with a specific reason on any failure — the
    caller (auth dependency) is responsible for turning that into a
    clean 401, not a stack trace."""
    settings = get_settings()
    if not settings.jwt_secret:
        raise InvalidSessionToken("Server has no session signing key configured.")
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.ExpiredSignatureError:
        raise InvalidSessionToken("Session expired.")
    except jwt.InvalidTokenError as e:
        raise InvalidSessionToken(f"Invalid session token: {e}")

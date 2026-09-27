from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.database import make_engine, make_session_factory
from opsec_platform.app.models import Session as SessionModel, User
from opsec_platform.app.security import decode_session_token, InvalidSessionToken

_engine = None
_SessionLocal = None


def configure_db(engine=None):
    """Call once at app startup (or per-test) to bind the dependency
    layer to a specific engine — lets tests use an isolated in-memory
    SQLite DB instead of the real platform.db file."""
    global _engine, _SessionLocal
    _engine = engine or make_engine()
    _SessionLocal = make_session_factory(_engine)


def get_db():
    if _SessionLocal is None:
        configure_db()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()


SESSION_COOKIE_NAME = "opsec_session"


def _extract_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[len("Bearer "):]
    return request.cookies.get(SESSION_COOKIE_NAME)


def get_current_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    try:
        claims = decode_session_token(token)
    except InvalidSessionToken as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    session_row = db.query(SessionModel).filter(SessionModel.id == claims["jti"]).first()
    if session_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session not found.")
    if session_row.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked.")
    if session_row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired.")

    user = db.query(User).filter(User.id == claims["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    return user


def get_current_user_optional(request: Request, db: DBSession = Depends(get_db)) -> User | None:
    """Same as get_current_user, but returns None instead of raising when
    there's no valid session — for routes like /auth/register that need
    to behave differently for an unauthenticated caller (bootstrapping a
    brand-new org) vs an authenticated one (adding a user to an org that
    already exists), rather than unconditionally requiring a session."""
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None

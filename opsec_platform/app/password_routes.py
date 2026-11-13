"""
Password change, forgot-password and reset.

- POST /auth/password          change (or, for an SSO-only account, set) the
                               signed-in user's password. Browser session only,
                               never a CLI access token.
- POST /auth/forgot-password   always answers 202 with the same message, so it
                               cannot be used to discover accounts; when the
                               account exists, a reset link is emailed.
- POST /auth/reset-password    sets a new password from a reset token.

Reset tokens are JWS (same signing key as sessions) with a distinct audience,
so they can never be accepted as a session token (PyJWT rejects a token with
an `aud` claim when no audience is expected) and a session token can never be
accepted here. They expire after 30 minutes and are single-use: each embeds a
keyed fingerprint of the password hash at issue time, so the first successful
reset (or any password change) invalidates every outstanding link.

The link carries the token in the URL fragment (/login#reset=...), which
browsers never send to a server, so it does not land in Vercel/Render request
logs. Every change and reset revokes the account's other sessions.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.activity import EventType, count_recent, log_activity
from opsec_platform.app.client_ip import client_meta
from opsec_platform.app.config import get_settings
from opsec_platform.app.dependencies import _extract_token, get_current_user, get_db
from opsec_platform.app.models import Session as SessionModel, User
from opsec_platform.app.security import _require_jwt_secret, decode_session_token, hash_password, verify_password

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

RESET_AUDIENCE = "opsec-password-reset"
RESET_TTL_MINUTES = 30
# An SSO-only account may set its first password only from a fresh sign-in,
# so a stolen long-lived session cannot quietly add a password backdoor.
FIRST_PASSWORD_MAX_SESSION_AGE = timedelta(minutes=15)
CHANGE_FAILURES_PER_15_MIN = 5
RESET_REQUESTS_PER_IP_PER_HOUR = 5
RESET_REQUESTS_PER_ACCOUNT_PER_HOUR = 3
GENERIC_RESET_REPLY = {"detail": "If an account exists for that email, a reset link is on its way."}


def _password(value: str) -> str:
    if len(value) < 8:
        raise ValueError("Use at least 8 characters.")
    if len(value.encode("utf-8")) > 72:
        raise ValueError("Password is too long. Use a passphrase of 72 UTF-8 bytes or fewer.")
    return value


class ChangePasswordRequest(BaseModel):
    current_password: str | None = Field(default=None, max_length=128)
    new_password: str = Field(max_length=128)

    @field_validator("new_password")
    @classmethod
    def _valid_password(cls, value: str) -> str:
        return _password(value)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=10, max_length=2048)
    new_password: str = Field(max_length=128)

    @field_validator("new_password")
    @classmethod
    def _valid_password(cls, value: str) -> str:
        return _password(value)


def password_reset_available() -> bool:
    from opsec_platform.app.alerts import smtp_configured

    return smtp_configured()


def _hash_fingerprint(user: User) -> str:
    secret = _require_jwt_secret().encode("utf-8")
    material = (user.hashed_password or "no-password").encode("utf-8")
    return hmac.new(secret, b"pwreset:" + material, hashlib.sha256).hexdigest()[:32]


def create_reset_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "aud": RESET_AUDIENCE,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=RESET_TTL_MINUTES),
        "pwf": _hash_fingerprint(user),
    }
    return jwt.encode(payload, _require_jwt_secret(), algorithm=get_settings().jwt_algorithm)


def _user_from_reset_token(db: DBSession, token: str) -> User | None:
    try:
        claims = jwt.decode(
            token, _require_jwt_secret(), algorithms=[get_settings().jwt_algorithm],
            audience=RESET_AUDIENCE, options={"require": ["exp", "iat", "sub", "aud", "pwf"]},
        )
    except jwt.InvalidTokenError:
        return None
    user = db.get(User, str(claims["sub"]))
    if user is None or not user.is_active:
        return None
    if not hmac.compare_digest(str(claims["pwf"]), _hash_fingerprint(user)):
        return None  # already used, or the password changed since it was issued
    return user


def _revoke_sessions(db: DBSession, user: User, keep_session_id: str | None = None) -> int:
    query = db.query(SessionModel).filter(SessionModel.user_id == user.id, SessionModel.revoked.is_(False))
    if keep_session_id:
        query = query.filter(SessionModel.id != keep_session_id)
    return query.update({SessionModel.revoked: True}, synchronize_session=False)


def _send_reset_email(user: User, token: str) -> None:
    from opsec_platform.app.alerts import send_mail

    link = f"{get_settings().base_url.rstrip('/')}/login#reset={token}"
    body = (
        "Someone (hopefully you) asked to reset the password for your OPSEC Scanner account.\n\n"
        f"Open this link within {RESET_TTL_MINUTES} minutes to choose a new password:\n\n{link}\n\n"
        "If you did not ask for this, ignore this email; your password stays the same.\n"
        "Resetting signs you out everywhere else.\n"
    )
    send_mail(user.email, "Reset your OPSEC Scanner password", body)


@router.post("/password")
def change_password(payload: ChangePasswordRequest, request: Request, db: DBSession = Depends(get_db),
                    user: User = Depends(get_current_user)):
    ip, ua = client_meta(request)
    session_id = str(decode_session_token(_extract_token(request) or "")["jti"])

    if user.hashed_password:
        if count_recent(db, [EventType.PASSWORD_CHANGE_FAILED], 15, user_id=user.id) >= CHANGE_FAILURES_PER_15_MIN:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                detail="Too many failed attempts. Try again later.")
        if not payload.current_password or not verify_password(payload.current_password, user.hashed_password):
            log_activity(db, EventType.PASSWORD_CHANGE_FAILED, user_id=user.id, ip_address=ip, user_agent=ua,
                         detail="wrong current password")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")
        if verify_password(payload.new_password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="The new password must be different from the current one.")
    else:
        current = db.get(SessionModel, session_id)
        created = current.created_at if current else None
        if created is not None and created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created is None or datetime.now(timezone.utc) - created > FIRST_PASSWORD_MAX_SESSION_AGE:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Sign out and sign in again, then set a password within 15 minutes.")

    added = not user.hashed_password
    user.hashed_password = hash_password(payload.new_password)
    revoked = _revoke_sessions(db, user, keep_session_id=session_id)
    db.commit()
    log_activity(db, EventType.PASSWORD_CHANGED, user_id=user.id, ip_address=ip, user_agent=ua,
                 detail="password added" if added else "password changed")
    return {"detail": "Password set." if added else "Password changed.", "other_sessions_revoked": revoked}


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: DBSession = Depends(get_db)):
    ip, ua = client_meta(request)
    email = str(payload.email).lower()
    if not password_reset_available():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Password reset by email is not enabled on this server. Contact your administrator.")
    if count_recent(db, [EventType.PASSWORD_RESET_REQUESTED], 60, ip_address=ip) >= RESET_REQUESTS_PER_IP_PER_HOUR:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many reset requests. Try again later.")

    user = db.query(User).filter(User.email == email).first()
    log_activity(db, EventType.PASSWORD_RESET_REQUESTED, user_id=user.id if user else None,
                 ip_address=ip, user_agent=ua, detail=None if user else "unknown email")
    # Same reply in every case below: no account enumeration.
    if user is None or not user.is_active:
        return GENERIC_RESET_REPLY
    if count_recent(db, [EventType.PASSWORD_RESET_REQUESTED], 60, user_id=user.id) > RESET_REQUESTS_PER_ACCOUNT_PER_HOUR:
        return GENERIC_RESET_REPLY  # don't let anyone flood a mailbox
    try:
        _send_reset_email(user, create_reset_token(user))
    except Exception:
        logger.exception("Could not send password reset email")
    return GENERIC_RESET_REPLY


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, db: DBSession = Depends(get_db)):
    ip, ua = client_meta(request)
    if count_recent(db, [EventType.PASSWORD_RESET_FAILED], 15, ip_address=ip) >= 10:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many attempts. Try again later.")
    user = _user_from_reset_token(db, payload.token)
    if user is None:
        log_activity(db, EventType.PASSWORD_RESET_FAILED, ip_address=ip, user_agent=ua, detail="invalid or used token")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="This reset link is invalid, expired or already used. Request a new one.")
    user.hashed_password = hash_password(payload.new_password)
    _revoke_sessions(db, user)
    db.commit()
    log_activity(db, EventType.PASSWORD_RESET_COMPLETED, user_id=user.id, ip_address=ip, user_agent=ua)
    return {"detail": "Password updated. Sign in with your new password."}

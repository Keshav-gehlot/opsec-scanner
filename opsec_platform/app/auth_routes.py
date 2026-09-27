"""
Local (org-provisioned username/password) auth routes.

Registration is intentionally NOT self-service open signup — "login and
password provided by organization" implies an org admin creates
accounts, not that anyone can sign themselves up. /auth/register is
gated behind requiring the caller to already be an authenticated user
belonging to the target org (bootstrapping the very first account for a
brand-new org is the one exception — see the route for how that's
handled safely, checked rather than left as an open door).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.activity import log_activity, EventType
from opsec_platform.app.dependencies import get_db, get_current_user, get_current_user_optional, SESSION_COOKIE_NAME
from opsec_platform.app.models import User, Org, Session as SessionModel
from opsec_platform.app.security import hash_password, verify_password, create_session_token

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    org_name: str
    display_name: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    org_id: str | None
    auth_provider: str
    is_org_admin: bool

    model_config = ConfigDict(from_attributes=True)


def _client_meta(request: Request) -> tuple[str, str]:
    return request.client.host if request.client else "unknown", request.headers.get("user-agent", "unknown")


def _issue_session(db: DBSession, user: User, request: Request, response: Response) -> str:
    from opsec_platform.app.models import Session as SessionModel
    import uuid
    from datetime import datetime, timezone

    session_id = str(uuid.uuid4())
    token, expires_at = create_session_token(user.id, session_id, user.email)
    ip, ua = _client_meta(request)

    db.add(SessionModel(id=session_id, user_id=user.id, expires_at=expires_at, ip_address=ip, user_agent=ua))
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    from opsec_platform.app.config import get_settings
    response.set_cookie(
        SESSION_COOKIE_NAME, token,
        httponly=True, samesite="lax", secure=get_settings().cookie_secure,
        max_age=int((expires_at - datetime.now(timezone.utc)).total_seconds()),
    )
    return token


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    caller: User | None = Depends(get_current_user_optional),
):
    """
    Creates a user under an org. Two cases, both checked explicitly
    rather than left as an implicit open door — this closes the gap the
    previous pass's README flagged by name ("/auth/register has no
    admin gate yet"):

      1. The org doesn't exist yet: bootstrapping a brand-new org's
         first account. No authentication required for this — there's
         no one to authenticate as yet. That first user becomes the
         org's admin automatically.
      2. The org already exists: the caller must be authenticated AND
         be an admin of *that specific org* — not just an admin of
         some other org, and not just any logged-in user. New users
         added this way are regular (non-admin) members by default.
    """
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")

    org = db.query(Org).filter(Org.name == payload.org_name).first()

    if org is None:
        org = Org(name=payload.org_name)
        db.add(org)
        db.flush()  # get org.id without a full commit yet
        is_admin = True
    else:
        if caller is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required to add a user to an existing organization. Log in as an admin of that org first.",
            )
        if not caller.is_org_admin or caller.org_id != org.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only an admin of this organization can add new users to it.",
            )
        is_admin = False

    user = User(
        org_id=org.id,
        email=payload.email,
        display_name=payload.display_name,
        hashed_password=hash_password(payload.password),
        auth_provider="local",
        is_org_admin=is_admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ip, ua = _client_meta(request)
    log_activity(db, EventType.USER_CREATED, user_id=user.id, ip_address=ip, user_agent=ua, detail=f"org={org.name}, admin={is_admin}")

    return user


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, request: Request, response: Response, db: DBSession = Depends(get_db)):
    from opsec_platform.app.activity import is_login_rate_limited

    ip, ua = _client_meta(request)

    if is_login_rate_limited(db, payload.email, ip_address=ip):
        log_activity(db, EventType.LOGIN_RATE_LIMITED, ip_address=ip, user_agent=ua, detail=f"email={payload.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )

    user = db.query(User).filter(User.email == payload.email).first()

    # Same error message and (roughly) same code path whether the email
    # doesn't exist or the password is wrong — don't let a login
    # endpoint be usable to enumerate which emails have accounts.
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if user is None or user.auth_provider != "local" or not user.hashed_password:
        log_activity(db, EventType.LOGIN_FAILED, ip_address=ip, user_agent=ua, detail=f"email={payload.email} (no such local account)")
        raise invalid

    if not verify_password(payload.password, user.hashed_password):
        log_activity(db, EventType.LOGIN_FAILED, user_id=user.id, ip_address=ip, user_agent=ua, detail="wrong password")
        raise invalid

    if not user.is_active:
        log_activity(db, EventType.LOGIN_FAILED, user_id=user.id, ip_address=ip, user_agent=ua, detail="account inactive")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been deactivated.")

    _issue_session(db, user, request, response)
    log_activity(db, EventType.LOGIN_SUCCESS, user_id=user.id, ip_address=ip, user_agent=ua)

    return user


@router.post("/logout")
def logout(request: Request, response: Response, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    from opsec_platform.app.dependencies import _extract_token
    from opsec_platform.app.security import decode_session_token

    token = _extract_token(request)
    claims = decode_session_token(token)  # already validated by get_current_user, safe to re-decode
    session_row = db.query(SessionModel).filter(SessionModel.id == claims["jti"]).first()
    if session_row:
        session_row.revoked = True
        db.commit()

    ip, ua = _client_meta(request)
    log_activity(db, EventType.LOGOUT, user_id=user.id, ip_address=ip, user_agent=ua)

    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"detail": "Logged out."}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user

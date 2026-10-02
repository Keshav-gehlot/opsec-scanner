from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.activity import EventType, log_activity
from opsec_platform.app.dependencies import SESSION_COOKIE_NAME, _extract_token, get_current_user, get_current_user_optional, get_db
from opsec_platform.app.models import Org, Session as SessionModel, User
from opsec_platform.app.security import create_session_token, decode_session_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    org_name: str = Field(min_length=1, max_length=120)
    display_name: str | None = Field(default=None, max_length=120)

    @field_validator("org_name")
    @classmethod
    def normalize_org_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError("Organization name is required.")
        return value

    @field_validator("password")
    @classmethod
    def validate_bcrypt_length(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password is too long. Use a passphrase of 72 UTF-8 bytes or fewer.")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(max_length=128)


class MemberStatusRequest(BaseModel):
    is_active: bool | None = None
    is_org_admin: bool | None = None


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    org_id: str | None
    auth_provider: str
    is_org_admin: bool
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None
    model_config = ConfigDict(from_attributes=True)


class SessionOut(BaseModel):
    id: str
    created_at: datetime
    expires_at: datetime
    revoked: bool
    ip_address: str | None
    user_agent: str | None
    current: bool = False
    model_config = ConfigDict(from_attributes=True)


def _client_meta(request: Request) -> tuple[str, str]:
    return request.client.host if request.client else "unknown", request.headers.get("user-agent", "unknown")


def _issue_session(db: DBSession, user: User, request: Request, response: Response) -> None:
    session_id = str(uuid.uuid4())
    token, expires_at = create_session_token(user.id, session_id, user.email)
    ip, ua = _client_meta(request)
    db.add(SessionModel(id=session_id, user_id=user.id, expires_at=expires_at, ip_address=ip, user_agent=ua))
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    from opsec_platform.app.config import get_settings
    response.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, samesite="lax",
        secure=get_settings().cookie_secure,
        max_age=max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds())),
    )


def _current_session_id(request: Request) -> str:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    try:
        return str(decode_session_token(token)["jti"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session.")


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: DBSession = Depends(get_db), caller: User | None = Depends(get_current_user_optional)):
    existing_user = db.query(User).filter(User.email == str(payload.email).lower()).first()
    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists.")

    org = db.query(Org).filter(Org.name == payload.org_name).first()
    if org is None:
        org = Org(name=payload.org_name)
        db.add(org)
        db.flush()
        is_admin = True
    else:
        if caller is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required to add a user to an existing organization. Log in as an admin of that org first.")
        if not caller.is_org_admin or caller.org_id != org.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an admin of this organization can add new users to it.")
        is_admin = False

    user = User(
        org_id=org.id,
        email=str(payload.email).lower(),
        display_name=payload.display_name or str(payload.email).split("@")[0],
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
    email = str(payload.email).lower()

    if is_login_rate_limited(db, email, ip_address=ip):
        log_activity(db, EventType.LOGIN_RATE_LIMITED, ip_address=ip, user_agent=ua, detail="rate limit reached")
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts. Try again later.")

    user = db.query(User).filter(User.email == email).first()
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    if user is None or user.auth_provider != "local" or not user.hashed_password:
        log_activity(db, EventType.LOGIN_FAILED, ip_address=ip, user_agent=ua, detail="invalid local credentials")
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
    session_id = _current_session_id(request)
    row = db.query(SessionModel).filter(SessionModel.id == session_id, SessionModel.user_id == user.id).first()
    if row:
        row.revoked = True
        db.commit()
    ip, ua = _client_meta(request)
    log_activity(db, EventType.LOGOUT, user_id=user.id, ip_address=ip, user_agent=ua)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"detail": "Logged out."}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/sessions", response_model=list[SessionOut])
def sessions(request: Request, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    current_id = _current_session_id(request)
    rows = (
        db.query(SessionModel)
        .filter(SessionModel.user_id == user.id, SessionModel.revoked.is_(False), SessionModel.expires_at > datetime.now(timezone.utc))
        .order_by(SessionModel.created_at.desc()).limit(25).all()
    )
    return [SessionOut.model_validate(row, from_attributes=True).model_copy(update={"current": row.id == current_id}) for row in rows]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(session_id: str, request: Request, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    current_id = _current_session_id(request)
    row = db.query(SessionModel).filter(SessionModel.id == session_id, SessionModel.user_id == user.id).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")
    if row.id == current_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use sign out to revoke the current session.")
    row.revoked = True
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/sessions/revoke-others")
def revoke_other_sessions(request: Request, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    current_id = _current_session_id(request)
    changed = db.query(SessionModel).filter(
        SessionModel.user_id == user.id, SessionModel.id != current_id, SessionModel.revoked.is_(False)
    ).update({SessionModel.revoked: True}, synchronize_session=False)
    db.commit()
    return {"revoked": changed}


@router.get("/org/members", response_model=list[UserOut])
def org_members(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    if not user.is_org_admin or not user.org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only organization admins can view members.")
    return db.query(User).filter(User.org_id == user.org_id).order_by(User.created_at.asc()).all()


@router.patch("/org/members/{member_id}", response_model=UserOut)
def update_org_member(
    member_id: str,
    payload: MemberStatusRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not user.is_org_admin or not user.org_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only organization admins can manage members.")
    member = db.query(User).filter(User.id == member_id, User.org_id == user.org_id).first()
    if member is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found.")
    if payload.is_active is False and member.id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account.")

    def has_other_active_admin() -> bool:
        return db.query(User).filter(
            User.org_id == user.org_id, User.is_org_admin.is_(True), User.is_active.is_(True), User.id != member.id
        ).first() is not None

    if member.is_org_admin and ((payload.is_active is False) or (payload.is_org_admin is False)) and not has_other_active_admin():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The organization must keep at least one active admin.")

    if payload.is_active is not None:
        member.is_active = payload.is_active
        if not payload.is_active:
            db.query(SessionModel).filter(SessionModel.user_id == member.id).update({SessionModel.revoked: True}, synchronize_session=False)
    if payload.is_org_admin is not None:
        member.is_org_admin = payload.is_org_admin

    db.commit()
    db.refresh(member)
    ip, ua = _client_meta(request)
    log_activity(db, EventType.USER_CREATED, user_id=user.id, ip_address=ip, user_agent=ua, detail=f"member_updated={member.id}")
    return member

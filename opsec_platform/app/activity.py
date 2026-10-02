from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.config import get_settings
from opsec_platform.app.models import ActivityLog, User


class EventType:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGIN_RATE_LIMITED = "login_rate_limited"
    OAUTH_LOGIN_SUCCESS = "oauth_login_success"
    OAUTH_LOGIN_FAILED = "oauth_login_failed"
    LOGOUT = "logout"
    USER_CREATED = "user_created"
    MEMBER_UPDATED = "member_updated"
    SCAN_REPORTED = "scan_reported"

    ALL = {
        LOGIN_SUCCESS, LOGIN_FAILED, LOGIN_RATE_LIMITED, OAUTH_LOGIN_SUCCESS, OAUTH_LOGIN_FAILED,
        LOGOUT, USER_CREATED, MEMBER_UPDATED, SCAN_REPORTED,
    }


def log_activity(
    db: DBSession,
    event_type: str,
    user_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    detail: str | None = None,
) -> ActivityLog:
    if event_type not in EventType.ALL:
        raise ValueError(f"Unknown activity event_type: {event_type!r}")
    entry = ActivityLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent,
        detail=detail,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def is_login_rate_limited(db: DBSession, email: str, ip_address: str | None = None) -> bool:
    settings = get_settings()
    email_window_start = datetime.now(timezone.utc) - timedelta(minutes=settings.login_rate_limit_window_minutes)
    ip_window_start = datetime.now(timezone.utc) - timedelta(minutes=settings.login_ip_rate_limit_window_minutes)

    user = db.query(User).filter(User.email == email).first()
    email_query = db.query(ActivityLog).filter(
        ActivityLog.event_type == EventType.LOGIN_FAILED,
        ActivityLog.timestamp >= email_window_start,
    )
    if user is not None:
        email_count = email_query.filter(ActivityLog.user_id == user.id).count()
    else:
        email_count = email_query.filter(ActivityLog.detail.like(f"email={email}%")).count()

    if email_count >= settings.login_rate_limit_attempts:
        return True

    if ip_address is not None:
        ip_count = db.query(ActivityLog).filter(
            ActivityLog.event_type == EventType.LOGIN_FAILED,
            ActivityLog.timestamp >= ip_window_start,
            ActivityLog.ip_address == ip_address,
        ).count()
        if ip_count >= settings.login_ip_rate_limit_attempts:
            return True

    return False

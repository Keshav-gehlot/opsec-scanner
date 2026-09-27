from __future__ import annotations

from pydantic import BaseModel, ConfigDict
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.dependencies import get_db, get_current_user
from opsec_platform.app.models import ActivityLog, User

router = APIRouter(prefix="/activity", tags=["activity"])


class ActivityOut(BaseModel):
    id: int
    user_id: str | None
    event_type: str
    timestamp: datetime
    ip_address: str | None
    detail: str | None

    model_config = ConfigDict(from_attributes=True)


@router.get("/me", response_model=list[ActivityOut])
def my_activity(
    limit: int = Query(default=50, le=200),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """A person's own activity history — logins, logouts, scans reported
    under their account. Everyone can see their own; org-wide visibility
    (an admin seeing every member's activity) is a natural v2 addition,
    gated on an is_org_admin flag this reference schema doesn't have yet."""
    rows = (
        db.query(ActivityLog)
        .filter(ActivityLog.user_id == user.id)
        .order_by(ActivityLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return rows


@router.post("/report-scan", status_code=201)
def report_scan(
    detail: str,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Opt-in endpoint for the CLI's --report-activity flag. The scanner
    itself stays local-first and offline by default — this only gets
    called if the person running it explicitly asks to report a scan
    summary here, and authenticates to do it. Never called automatically.
    """
    from opsec_platform.app.activity import log_activity, EventType
    entry = log_activity(db, EventType.SCAN_REPORTED, user_id=user.id, detail=detail)
    return {"id": entry.id, "logged_at": entry.timestamp.isoformat()}

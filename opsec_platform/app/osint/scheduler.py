"""
Recurring monitoring: re-scans verified targets on their daily/weekly
schedule.

Runs as one daemon thread per process. Several workers or instances can
run it at once: each due target is claimed with a conditional UPDATE on
next_run_at, so only one process starts the scan. On hosts that sleep when
idle (Render's free plan) runs are simply caught up on the next wake.
Disable with PLATFORM_SCHEDULER_ENABLED=false.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import update

from opsec_platform.app import scan_service as svc
from opsec_platform.app.models import MonitoredTarget, User
from opsec_platform.app.osint import service

logger = logging.getLogger(__name__)
_started = False
_lock = threading.Lock()


def run_due(now: datetime | None = None, submit=None) -> list[str]:
    """Start scans for every due target this process manages to claim.
    Returns the started scan ids."""
    now = now or datetime.now(timezone.utc)
    submit = submit or svc.submit
    db = svc._session()
    started = []
    try:
        due = db.query(MonitoredTarget).filter(
            MonitoredTarget.schedule != "none",
            MonitoredTarget.verified_at.isnot(None),
            MonitoredTarget.next_run_at.isnot(None),
            MonitoredTarget.next_run_at <= now,
        ).limit(20).all()
        for target in due:
            claimed = db.execute(
                update(MonitoredTarget)
                .where(MonitoredTarget.id == target.id, MonitoredTarget.next_run_at == target.next_run_at)
                .values(next_run_at=service.next_run(target.schedule, now))
            ).rowcount
            db.commit()
            if not claimed:
                continue
            user = db.get(User, target.user_id)
            if user is None or not user.is_active:
                continue
            profile = svc.load_profile_data(db, user)
            scan = service.create_target_scan(db, target)
            submit(service.run_target_scan, scan.id, target.id, profile)
            started.append(scan.id)
    except Exception:
        logger.exception("Scheduler pass failed")
        db.rollback()
    finally:
        db.close()
    return started


def _loop(interval: int) -> None:
    while True:
        time.sleep(interval)
        run_due()


def start() -> bool:
    global _started
    if os.environ.get("PLATFORM_SCHEDULER_ENABLED", "true").lower() == "false":
        return False
    with _lock:
        if _started:
            return False
        interval = max(30, int(os.environ.get("PLATFORM_SCHEDULER_INTERVAL_SECONDS", "300") or 300))
        threading.Thread(target=_loop, args=(interval,), name="opsec-scheduler", daemon=True).start()
        _started = True
    return True

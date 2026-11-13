"""
Machine-to-machine endpoints, off unless their token is configured.

POST /internal/scheduler/run — start every due monitoring scan now.
The free Render plan sleeps when idle, so the in-process scheduler only runs
while something keeps the instance awake. The daily keep-alive workflow
calls this with `Authorization: Bearer $PLATFORM_SCHEDULER_TOKEN`, so daily
schedules run at a known time instead of whenever someone next visits.
Returns 404 when PLATFORM_SCHEDULER_TOKEN is unset (endpoint disabled).
"""

from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, HTTPException, Request, status

router = APIRouter(prefix="/internal", tags=["internal"], include_in_schema=False)

MIN_TOKEN_BYTES = 32


def _token() -> str:
    return os.environ.get("PLATFORM_SCHEDULER_TOKEN", "").strip()


@router.post("/scheduler/run")
def run_scheduler(request: Request):
    token = _token()
    if len(token.encode()) < MIN_TOKEN_BYTES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    supplied = request.headers.get("authorization", "")
    if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid scheduler token.")
    from opsec_platform.app.osint import scheduler

    started = scheduler.run_due()
    return {"started": len(started)}

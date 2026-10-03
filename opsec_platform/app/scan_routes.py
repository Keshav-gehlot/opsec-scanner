"""
Scan workspace API: import CLI results, run media / public-repo scans,
browse findings, compare scans, export, and the Operations Center overview.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app import scan_service as svc
from opsec_platform.app.activity import EventType, log_activity
from opsec_platform.app.config import get_settings
from opsec_platform.app.dependencies import get_api_user, get_current_user, get_db
from opsec_platform.app.models import Finding, Scan, User

router = APIRouter(prefix="/scans", tags=["scans"])
profile_router = APIRouter(prefix="/profile", tags=["profile"])

SOURCES = {"cli_upload", "json_import", "media_upload", "git_url"}
SORT_FIELDS = {"risk": Finding.risk_score, "rule": Finding.rule_id, "category": Finding.category, "origin": Finding.origin}


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

class ScanOut(BaseModel):
    id: str
    user_id: str
    source: str
    target_label: str
    status: str
    error: str | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    max_risk_score: float
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    stats: dict = {}
    owner_email: str | None = None
    model_config = ConfigDict(from_attributes=True)


class FindingOut(BaseModel):
    id: int
    fingerprint: str
    risk_score: float
    risk_label: str
    rule_id: str
    category: str
    preview: str
    matched_length: int
    base_severity: float | None
    entropy_score: float | None
    identity_confidence: float | None
    identity_reason: str | None
    exposure_level: str | None
    source_type: str | None
    origin: str | None
    context: str | None
    occurrence_count: int
    model_config = ConfigDict(from_attributes=True)


class GitScanRequest(BaseModel):
    url: str = Field(min_length=10, max_length=300)
    depth: int | None = Field(default=None, ge=1)
    label: str | None = Field(default=None, max_length=120)


class IdentityProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    aliases: list[str] = Field(default_factory=list, max_length=25)
    emails: list[str] = Field(default_factory=list, max_length=25)
    domains: list[str] = Field(default_factory=list, max_length=25)
    github_handles: list[str] = Field(default_factory=list, max_length=25)
    home_coordinates: list[float] | None = None

    @field_validator("aliases", "emails", "domains", "github_handles")
    @classmethod
    def clean_list(cls, values: list[str]) -> list[str]:
        cleaned = []
        for value in values:
            value = " ".join(str(value).split())[:120]
            if value and value.lower() not in {v.lower() for v in cleaned}:
                cleaned.append(value)
        return cleaned

    @field_validator("home_coordinates")
    @classmethod
    def check_coordinates(cls, value):
        if value is None:
            return None
        if len(value) != 2 or not (-90 <= value[0] <= 90 and -180 <= value[1] <= 180):
            raise ValueError("home_coordinates must be [latitude, longitude].")
        return value


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _client_meta(request: Request) -> tuple[str, str]:
    from opsec_platform.app.client_ip import client_meta

    return client_meta(request)


def _scan_out(scan: Scan, owner_email: str | None = None) -> ScanOut:
    try:
        stats = json.loads(scan.stats) if scan.stats else {}
    except json.JSONDecodeError:
        stats = {}
    data = {name: getattr(scan, name) for name in ScanOut.model_fields if name not in ("stats", "owner_email")}
    return ScanOut(**data, stats=stats if isinstance(stats, dict) else {}, owner_email=owner_email)


def _visible_scans(db: DBSession, user: User, scope: str = "mine"):
    query = db.query(Scan)
    if scope == "org":
        if not user.is_org_admin or not user.org_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only organization admins can view organization scans.")
        return query.filter(Scan.org_id == user.org_id)
    return query.filter(Scan.user_id == user.id)


def _get_scan(db: DBSession, user: User, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    if scan.user_id == user.id:
        return scan
    if user.is_org_admin and user.org_id and scan.org_id == user.org_id:
        return scan
    # Same response as a missing scan: do not confirm other users' scan ids.
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")


def _check_quota(db: DBSession, user: User, server_side: bool) -> None:
    settings = get_settings()
    if server_side and not settings.web_scans_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Server-side scans are disabled on this deployment. Import CLI results instead.")
    since = datetime.now(timezone.utc) - timedelta(days=1)
    today = db.query(func.count(Scan.id)).filter(Scan.user_id == user.id, Scan.created_at >= since).scalar() or 0
    if today >= settings.scan_daily_limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Daily scan limit reached. Try again later.")
    if server_side:
        active = db.query(func.count(Scan.id)).filter(
            Scan.user_id == user.id, Scan.status.in_(("queued", "running"))
        ).scalar() or 0
        if active >= 2:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="You already have scans running. Wait for them to finish.")


def _new_scan(db: DBSession, user: User, source: str, label: str) -> Scan:
    scan = Scan(user_id=user.id, org_id=user.org_id, source=source, target_label=label[:200], status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _clean_label(label: str | None, fallback: str) -> str:
    label = " ".join((label or "").split())[:120]
    return label or fallback


async def _read_limited(upload: UploadFile, limit: int, what: str) -> bytes:
    chunks, size = [], 0
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"{what} exceeds the {limit // (1024 * 1024)} MB limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def _previous_scan(db: DBSession, scan: Scan) -> Scan | None:
    return (
        db.query(Scan)
        .filter(
            Scan.user_id == scan.user_id,
            Scan.target_label == scan.target_label,
            Scan.status == "completed",
            Scan.id != scan.id,
            Scan.created_at < scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


def _fingerprints(db: DBSession, scan_id: str) -> set[str]:
    return {row[0] for row in db.query(Finding.fingerprint).filter(Finding.scan_id == scan_id).all()}


# --------------------------------------------------------------------------
# Capabilities / listing
# --------------------------------------------------------------------------

@router.get("/capabilities")
def scan_capabilities(user: User = Depends(get_api_user)):
    return svc.capabilities()


@router.get("", response_model=list[ScanOut])
def list_scans(
    scope: str = Query(default="mine", pattern="^(mine|org)$"),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(queued|running|completed|failed)$"),
    q: str | None = Query(default=None, max_length=120),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    query = _visible_scans(db, user, scope)
    if status_filter:
        query = query.filter(Scan.status == status_filter)
    if q:
        query = query.filter(Scan.target_label.ilike(f"%{q}%"))
    rows = query.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
    emails = {}
    if scope == "org":
        ids = {r.user_id for r in rows}
        emails = {u.id: u.email for u in db.query(User).filter(User.id.in_(ids)).all()} if ids else {}
    return [_scan_out(r, emails.get(r.user_id)) for r in rows]


@router.get("/overview")
def overview(
    scope: str = Query(default="mine", pattern="^(mine|org)$"),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    """Operations Center: aggregate posture across completed scans."""
    base = _visible_scans(db, user, scope)
    completed = base.filter(Scan.status == "completed").order_by(Scan.created_at.asc()).all()
    status_counts = dict(
        base.with_entities(Scan.status, func.count(Scan.id)).group_by(Scan.status).all()
    )

    # Latest completed scan per target, with diff against that target's previous scan.
    by_target: dict[str, list[Scan]] = {}
    for scan in completed:
        by_target.setdefault((scan.user_id, scan.target_label), []).append(scan)

    targets = []
    open_totals = Counter()
    for (_, label), scans in by_target.items():
        latest = scans[-1]
        previous = scans[-2] if len(scans) > 1 else None
        current_fp = _fingerprints(db, latest.id)
        previous_fp = _fingerprints(db, previous.id) if previous else set()
        open_totals.update({
            "CRITICAL": latest.critical_count, "HIGH": latest.high_count,
            "MEDIUM": latest.medium_count, "LOW": latest.low_count,
        })
        targets.append({
            "target_label": label,
            "latest_scan_id": latest.id,
            "latest_at": latest.created_at,
            "source": latest.source,
            "scans": len(scans),
            "total_findings": latest.total_findings,
            "critical": latest.critical_count,
            "high": latest.high_count,
            "medium": latest.medium_count,
            "low": latest.low_count,
            "max_risk_score": latest.max_risk_score,
            "new": len(current_fp - previous_fp) if previous else None,
            "resolved": len(previous_fp - current_fp) if previous else None,
        })
    targets.sort(key=lambda t: (t["critical"], t["high"], t["max_risk_score"]), reverse=True)

    latest_ids = [t["latest_scan_id"] for t in targets]
    top_rules = []
    categories = []
    if latest_ids:
        top_rules = [
            {"rule_id": rule, "count": count}
            for rule, count in db.query(Finding.rule_id, func.count(Finding.id))
            .filter(Finding.scan_id.in_(latest_ids)).group_by(Finding.rule_id)
            .order_by(func.count(Finding.id).desc()).limit(8).all()
        ]
        categories = [
            {"category": cat, "count": count}
            for cat, count in db.query(Finding.category, func.count(Finding.id))
            .filter(Finding.scan_id.in_(latest_ids)).group_by(Finding.category)
            .order_by(func.count(Finding.id).desc()).all()
        ]

    trend = [
        {
            "scan_id": s.id, "target_label": s.target_label, "created_at": s.created_at,
            "critical": s.critical_count, "high": s.high_count, "medium": s.medium_count, "low": s.low_count,
            "total": s.total_findings,
        }
        for s in completed[-30:]
    ]
    return {
        "scope": scope,
        "scans_total": sum(status_counts.values()),
        "scans_by_status": status_counts,
        "targets": targets,
        "open_findings": {label: open_totals.get(label, 0) for label in svc.RISK_LABELS},
        "top_rules": top_rules,
        "categories": categories,
        "trend": trend,
    }


# --------------------------------------------------------------------------
# Creating scans
# --------------------------------------------------------------------------

@router.post("/import", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
async def import_findings(
    request: Request,
    label: str | None = Query(default=None, max_length=120),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    """Import a findings JSON produced by the CLI. Accepts the body as
    application/json (the CLI's --upload-findings) or as a multipart file
    field named ``file`` (browser upload)."""
    settings = get_settings()
    limit = settings.scan_import_max_mb * 1024 * 1024
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if upload is None or not hasattr(upload, "read"):
            raise HTTPException(status_code=400, detail="Attach the findings JSON file as 'file'.")
        raw = await _read_limited(upload, limit, "Findings file")
        label = label or (form.get("label") if isinstance(form.get("label"), str) else None)
        default_label = (getattr(upload, "filename", "") or "imported findings").rsplit(".", 1)[0]
    else:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Findings payload is too large.")
        raw = b""
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > limit:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Findings payload is too large.")
        default_label = "CLI upload"

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The file is not valid JSON.")

    try:
        records = svc.records_from_export(payload, settings.scan_import_max_findings)
    except svc.ScanInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    _check_quota(db, user, server_side=False)
    payload_label = payload.get("target_label") if isinstance(payload.get("target_label"), str) else None
    source = "cli_upload" if getattr(request.state, "auth_kind", "") == "api_token" else "json_import"
    scan = _new_scan(db, user, source, _clean_label(label or payload_label, default_label))
    stats = payload.get("scan_stats") if isinstance(payload.get("scan_stats"), dict) else {}
    stats = {k: v for k, v in stats.items() if isinstance(v, (int, float, str)) and len(str(v)) < 200}
    stats["imported_redacted"] = bool(payload.get("redacted", True))
    if isinstance(payload.get("generated_at"), str):
        stats["generated_at"] = payload["generated_at"][:40]
    scan.started_at = datetime.now(timezone.utc)
    svc.store_results(db, scan, records, stats)

    ip, ua = _client_meta(request)
    log_activity(db, EventType.SCAN_IMPORTED, user_id=user.id, ip_address=ip, user_agent=ua,
                 detail=f"{scan.target_label}: {scan.total_findings} findings ({source})")
    return _scan_out(scan)


@router.post("/media", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def media_scan(
    request: Request,
    files: list[UploadFile] = File(...),
    label: str | None = Form(default=None, max_length=120),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    settings = get_settings()
    _check_quota(db, user, server_side=True)
    if not files:
        raise HTTPException(status_code=400, detail="Attach at least one file.")
    if len(files) > settings.scan_media_max_files:
        raise HTTPException(status_code=400, detail=f"Upload at most {settings.scan_media_max_files} files per scan.")

    stored: list[tuple[str, bytes]] = []
    total, total_limit = 0, settings.scan_media_max_total_mb * 1024 * 1024
    for index, upload in enumerate(files, start=1):
        try:
            name = svc.safe_upload_name(upload.filename or "", index)
        except svc.ScanInputError as exc:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(exc))
        content = await _read_limited(upload, settings.scan_media_max_file_mb * 1024 * 1024, f"'{upload.filename}'")
        total += len(content)
        if total > total_limit:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Upload exceeds the {settings.scan_media_max_total_mb} MB total limit.")
        stored.append((name, content))

    default = files[0].filename if len(files) == 1 else f"{len(files)} uploaded files"
    scan = _new_scan(db, user, "media_upload", _clean_label(label, default or "media upload"))
    profile = svc.load_profile_data(db, user)
    svc.submit(svc.run_media_scan, scan.id, stored, profile)

    ip, ua = _client_meta(request)
    log_activity(db, EventType.SCAN_STARTED, user_id=user.id, ip_address=ip, user_agent=ua,
                 detail=f"media upload: {len(stored)} file(s)")
    return _scan_out(scan)


@router.post("/git", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
def git_scan(
    payload: GitScanRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    settings = get_settings()
    _check_quota(db, user, server_side=True)
    try:
        url = svc.normalize_git_url(payload.url)
    except svc.ScanInputError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    depth = min(payload.depth or settings.scan_git_default_depth, settings.scan_git_max_depth)
    label = _clean_label(payload.label, url.split("://", 1)[1])
    scan = _new_scan(db, user, "git_url", label)
    profile = svc.load_profile_data(db, user)
    svc.submit(svc.run_git_scan, scan.id, url, depth, profile)

    ip, ua = _client_meta(request)
    log_activity(db, EventType.SCAN_STARTED, user_id=user.id, ip_address=ip, user_agent=ua, detail=f"git: {url}")
    return _scan_out(scan)


# --------------------------------------------------------------------------
# Single scan
# --------------------------------------------------------------------------

@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: DBSession = Depends(get_db), user: User = Depends(get_api_user)):
    scan = _get_scan(db, user, scan_id)
    if scan.status in ("queued", "running"):
        svc.recover_stale_scans(db)
        db.refresh(scan)
    owner = db.get(User, scan.user_id)
    return _scan_out(scan, owner.email if owner else None)


@router.get("/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    risk: str | None = Query(default=None, max_length=60),
    category: str | None = Query(default=None, max_length=120),
    rule: str | None = Query(default=None, max_length=120),
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="risk", pattern="^(risk|rule|category|origin)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    scan = _get_scan(db, user, scan_id)
    query = db.query(Finding).filter(Finding.scan_id == scan.id)
    if risk:
        labels = [r.strip().upper() for r in risk.split(",") if r.strip().upper() in svc.RISK_LABELS]
        if labels:
            query = query.filter(Finding.risk_label.in_(labels))
    if category:
        query = query.filter(Finding.category == category)
    if rule:
        query = query.filter(Finding.rule_id == rule)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Finding.origin.ilike(like), Finding.context.ilike(like), Finding.rule_id.ilike(like), Finding.identity_reason.ilike(like)))
    total = query.count()
    column = SORT_FIELDS[sort]
    query = query.order_by(column.desc() if order == "desc" else column.asc(), Finding.id.asc())
    rows = query.offset(offset).limit(limit).all()

    facets_rows = db.query(Finding.risk_label, Finding.category, Finding.rule_id).filter(Finding.scan_id == scan.id).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [FindingOut.model_validate(r, from_attributes=True).model_dump() for r in rows],
        "facets": {
            "risk": dict(Counter(r[0] for r in facets_rows)),
            "category": dict(Counter(r[1] for r in facets_rows)),
            "rule": dict(Counter(r[2] for r in facets_rows)),
        },
    }


@router.get("/{scan_id}/diff")
def scan_diff(scan_id: str, db: DBSession = Depends(get_db), user: User = Depends(get_api_user)):
    """New / still-open / resolved findings versus the previous completed
    scan of the same target (same owner + target label)."""
    scan = _get_scan(db, user, scan_id)
    previous = _previous_scan(db, scan)
    if previous is None:
        return {"previous_scan_id": None, "new": [], "resolved": [], "still_open": 0}
    current = {f.fingerprint: f for f in db.query(Finding).filter(Finding.scan_id == scan.id).all()}
    before = {f.fingerprint: f for f in db.query(Finding).filter(Finding.scan_id == previous.id).all()}

    def brief(f: Finding) -> dict:
        return {"rule_id": f.rule_id, "risk_label": f.risk_label, "risk_score": f.risk_score,
                "preview": f.preview, "origin": f.origin, "category": f.category}

    return {
        "previous_scan_id": previous.id,
        "previous_created_at": previous.created_at,
        "new": [brief(f) for fp, f in current.items() if fp not in before][:200],
        "resolved": [brief(f) for fp, f in before.items() if fp not in current][:200],
        "still_open": len(current.keys() & before.keys()),
    }


@router.get("/{scan_id}/export")
def export_scan(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|csv|sarif)$"),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    scan = _get_scan(db, user, scan_id)
    rows = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.risk_score.desc()).all()
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in scan.target_label)[:60] or "scan"

    if format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        columns = ["risk_label", "risk_score", "rule_id", "category", "preview", "origin", "context",
                   "exposure_level", "identity_confidence", "occurrence_count", "fingerprint"]
        writer.writerow(columns)
        for r in rows:
            values = [getattr(r, c) for c in columns]
            # Neutralise spreadsheet formula injection from scanned content.
            writer.writerow([("'" + v) if isinstance(v, str) and v[:1] in "=+-@\t\r" else v for v in values])
        return Response(buffer.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{safe_name}.csv"'})

    if format == "sarif":
        levels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        rules = sorted({(r.rule_id, r.category) for r in rows})
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "opsec-scanner", "informationUri": "https://github.com/Keshav-gehlot/opsec-scanner",
                    "rules": [{"id": rid, "name": rid, "properties": {"category": cat}} for rid, cat in rules],
                }},
                "results": [{
                    "ruleId": r.rule_id,
                    "level": levels.get(r.risk_label, "note"),
                    "message": {"text": f"{r.risk_label} ({r.risk_score}) {r.category} finding: {r.preview} — {r.context or ''}".strip()},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": (r.origin or "unknown")[:500]}}}],
                    "partialFingerprints": {"opsecFingerprint/v1": r.fingerprint},
                    "properties": {"risk_score": r.risk_score, "exposure_level": r.exposure_level},
                } for r in rows],
            }],
        }
        return JSONResponse(sarif, headers={"Content-Disposition": f'attachment; filename="{safe_name}.sarif"'})

    body = {
        "scan": _scan_out(scan).model_dump(mode="json"),
        "redacted": True,
        "total_findings": len(rows),
        "findings": [FindingOut.model_validate(r, from_attributes=True).model_dump() for r in rows],
    }
    return JSONResponse(body, headers={"Content-Disposition": f'attachment; filename="{safe_name}.json"'})


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, request: Request, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    scan = _get_scan(db, user, scan_id)
    if scan.status in ("queued", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Wait for the scan to finish before deleting it.")
    db.query(Finding).filter(Finding.scan_id == scan.id).delete(synchronize_session=False)
    db.delete(scan)
    db.commit()
    ip, ua = _client_meta(request)
    log_activity(db, EventType.SCAN_DELETED, user_id=user.id, ip_address=ip, user_agent=ua, detail=scan.target_label)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------
# Identity profile
# --------------------------------------------------------------------------

@profile_router.get("/identity")
def get_identity_profile(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    return svc.load_profile_data(db, user)


@profile_router.put("/identity")
def put_identity_profile(payload: IdentityProfileIn, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    return svc.save_profile_data(db, user, payload.model_dump())

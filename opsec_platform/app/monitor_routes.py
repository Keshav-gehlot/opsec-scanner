"""
API for the monitoring modules: targets + verification, global findings
search and triage, executive summary / reports, identity graph, domain
intelligence, alert integrations and the rule catalog.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app import alerts, reports
from opsec_platform.app import scan_service as svc
from opsec_platform.app.activity import EventType, log_activity
from opsec_platform.app.client_ip import client_meta
from opsec_platform.app.dependencies import get_api_user, get_current_user, get_db
from opsec_platform.app.models import Finding, FindingState, Integration, MonitoredTarget, Scan, User
from opsec_platform.app.osint import service as monitor
from opsec_platform.app.osint import verification as verify

targets_router = APIRouter(prefix="/targets", tags=["monitoring"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])
reports_router = APIRouter(prefix="/reports", tags=["reports"])
intel_router = APIRouter(tags=["intelligence"])
integrations_router = APIRouter(prefix="/integrations", tags=["integrations"])

MAX_TARGETS = 20
MAX_INTEGRATIONS = 10


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

class TargetIn(BaseModel):
    kind: str = Field(pattern="^(domain|url|email|github_handle)$")
    value: str = Field(min_length=3, max_length=500)
    schedule: str = Field(default="none", pattern="^(none|daily|weekly)$")


class TargetPatch(BaseModel):
    schedule: str = Field(pattern="^(none|daily|weekly)$")


class VerifyIn(BaseModel):
    method: str | None = Field(default=None, pattern="^(dns_txt|well_known|gist|account_email|domain)$")


def _target_out(t: MonitoredTarget, include_token: bool = True) -> dict:
    return {
        "id": t.id, "kind": t.kind, "value": t.value, "verified": t.verified_at is not None,
        "verified_at": t.verified_at, "verification_method": t.verification_method, "schedule": t.schedule,
        "next_run_at": t.next_run_at, "last_scan_id": t.last_scan_id, "last_scan_at": t.last_scan_at,
        "created_at": t.created_at,
        "verification": verify.instructions(t.kind, t.value, t.verification_token) if include_token and t.verified_at is None else None,
    }


def _own_target(db: DBSession, user: User, target_id: str) -> MonitoredTarget:
    target = db.get(MonitoredTarget, target_id)
    if target is None or target.user_id != user.id:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target


@targets_router.get("")
def list_targets(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(MonitoredTarget).filter(MonitoredTarget.user_id == user.id).order_by(MonitoredTarget.created_at.asc()).all()
    return [_target_out(t) for t in rows]


@targets_router.post("", status_code=201)
def create_target(payload: TargetIn, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    try:
        value = verify.normalize(payload.kind, payload.value)
    except verify.TargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if db.query(MonitoredTarget).filter(MonitoredTarget.user_id == user.id).count() >= MAX_TARGETS:
        raise HTTPException(status_code=400, detail=f"At most {MAX_TARGETS} targets.")
    target = MonitoredTarget(user_id=user.id, org_id=user.org_id, kind=payload.kind, value=value,
                             verification_token=verify.new_token(), schedule=payload.schedule)
    db.add(target)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="You already monitor this target.")
    db.refresh(target)
    _try_auto_verify(db, user, target)
    return _target_out(target)


def _mark_verified(db: DBSession, target: MonitoredTarget, method: str) -> None:
    target.verified_at = datetime.now(timezone.utc)
    target.verification_method = method
    target.next_run_at = monitor.next_run(target.schedule)
    db.commit()


def _try_auto_verify(db: DBSession, user: User, target: MonitoredTarget) -> None:
    if target.kind == "email" and target.value == user.email.lower():
        _mark_verified(db, target, "account_email")
    elif target.kind == "url":
        host = verify.url_domain(target.value)
        if any(verify.domain_covers(d, host) for d in monitor.verified_domains_for(db, user.id)):
            _mark_verified(db, target, "domain")


@targets_router.post("/{target_id}/verify")
def verify_target(target_id: str, payload: VerifyIn, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = _own_target(db, user, target_id)
    if target.verified_at is not None:
        return _target_out(target)
    ok, method = False, payload.method
    if target.kind == "domain":
        if method in (None, "dns_txt") and verify.check_dns_txt(target.value, target.verification_token):
            ok, method = True, "dns_txt"
        elif method in (None, "well_known") and verify.check_well_known(target.value, target.verification_token):
            ok, method = True, "well_known"
    elif target.kind == "github_handle":
        ok, method = verify.check_github_gist(target.value, target.verification_token), "gist"
    else:
        _try_auto_verify(db, user, target)
        ok, method = target.verified_at is not None, target.verification_method
    if not ok:
        hint = {
            "domain": "Token not found yet. DNS changes can take a few minutes to propagate.",
            "github_handle": "No public gist by this account mentions the token yet.",
            "email": "Only your account's own email address can be monitored.",
            "url": "Verify the URL's domain first.",
        }[target.kind]
        raise HTTPException(status_code=400, detail=hint)
    if target.verified_at is None:
        _mark_verified(db, target, method)
    return _target_out(target)


@targets_router.patch("/{target_id}")
def update_target(target_id: str, payload: TargetPatch, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = _own_target(db, user, target_id)
    target.schedule = payload.schedule
    target.next_run_at = monitor.next_run(payload.schedule) if target.verified_at else None
    db.commit()
    return _target_out(target)


@targets_router.delete("/{target_id}", status_code=204)
def delete_target(target_id: str, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    target = _own_target(db, user, target_id)
    db.delete(target)
    db.commit()
    return Response(status_code=204)


@targets_router.post("/{target_id}/scan", status_code=202)
def scan_target(target_id: str, request: Request, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    from opsec_platform.app.scan_routes import _check_quota, _scan_out

    target = _own_target(db, user, target_id)
    if target.verified_at is None:
        raise HTTPException(status_code=403, detail="Verify ownership of this target first.")
    _check_quota(db, user, server_side=True)
    profile = svc.load_profile_data(db, user)
    scan = monitor.create_target_scan(db, target)
    ip, ua = client_meta(request)
    log_activity(db, EventType.SCAN_STARTED, user_id=user.id, ip_address=ip, user_agent=ua, detail=f"monitor {target.kind}:{target.value}")
    out = _scan_out(scan)
    svc.submit(monitor.run_target_scan, scan.id, target.id, profile)
    return out


# --------------------------------------------------------------------------
# Findings: global search and triage
# --------------------------------------------------------------------------

class StatusIn(BaseModel):
    status: str = Field(pattern="^(open|in_review|resolved|suppressed|false_positive)$")
    note: str | None = Field(default=None, max_length=500)


def finding_dict(f: Finding, scan: Scan | None = None) -> dict:
    meta = svc.rule_meta().get(f.rule_id, {})
    return {
        "id": f.id, "scan_id": f.scan_id, "fingerprint": f.fingerprint, "risk_score": f.risk_score,
        "risk_label": f.risk_label, "rule_id": f.rule_id, "category": f.category, "preview": f.preview,
        "matched_length": f.matched_length, "origin": f.origin, "context": f.context, "status": f.status,
        "occurrence_count": f.occurrence_count, "exposure_level": f.exposure_level, "source_type": f.source_type,
        "identity_confidence": f.identity_confidence, "identity_reason": f.identity_reason,
        "entropy_score": f.entropy_score, "base_severity": f.base_severity,
        "mitre": meta.get("mitre"), "description": meta.get("description"),
        "target_label": scan.target_label if scan else None,
    }


@findings_router.get("")
def search_findings(
    q: str | None = Query(default=None, max_length=200),
    risk: str | None = Query(default=None, max_length=60),
    status_filter: str | None = Query(default=None, alias="status", max_length=80),
    category: str | None = Query(default=None, max_length=60),
    mitre: str | None = Query(default=None, max_length=20),
    latest_only: bool = True,
    scope: str = Query(default="mine", pattern="^(mine|org)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_api_user),
):
    if scope == "org" and (not user.is_org_admin or not user.org_id):
        raise HTTPException(status_code=403, detail="Only organization admins can search organization findings.")
    if latest_only:
        scans = reports.latest_scans(db, user.id, user.org_id, scope)
    else:
        base = db.query(Scan).filter(Scan.status == "completed")
        scans = (base.filter(Scan.org_id == user.org_id) if scope == "org" else base.filter(Scan.user_id == user.id)).all()
    scan_map = {s.id: s for s in scans}
    query = db.query(Finding).filter(Finding.scan_id.in_(list(scan_map) or [""]))
    if risk:
        labels = [r.strip().upper() for r in risk.split(",") if r.strip().upper() in svc.RISK_LABELS]
        if labels:
            query = query.filter(Finding.risk_label.in_(labels))
    if status_filter:
        wanted = [s for s in status_filter.split(",") if s in svc.TRIAGE_STATUSES]
        if wanted:
            query = query.filter(Finding.status.in_(wanted))
    if category:
        query = query.filter(Finding.category == category)
    if mitre:
        ids = [rid for rid, m in svc.rule_meta().items() if m.get("mitre") == mitre]
        query = query.filter(Finding.rule_id.in_(ids or [""]))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Finding.origin.ilike(like), Finding.context.ilike(like), Finding.rule_id.ilike(like),
                                 Finding.category.ilike(like), Finding.preview.ilike(like)))
    total = query.count()
    rows = query.order_by(Finding.risk_score.desc(), Finding.id.asc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [finding_dict(f, scan_map.get(f.scan_id)) for f in rows]}


@findings_router.patch("/{finding_id}/status")
def set_finding_status(finding_id: int, payload: StatusIn, request: Request, db: DBSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    finding = db.get(Finding, finding_id)
    scan = db.get(Scan, finding.scan_id) if finding else None
    if finding is None or scan is None or not (scan.user_id == user.id or (user.is_org_admin and user.org_id and scan.org_id == user.org_id)):
        raise HTTPException(status_code=404, detail="Finding not found.")
    state = db.query(FindingState).filter(FindingState.user_id == scan.user_id, FindingState.target_label == scan.target_label,
                                          FindingState.fingerprint == finding.fingerprint).first()
    if state is None:
        state = FindingState(user_id=scan.user_id, target_label=scan.target_label, fingerprint=finding.fingerprint)
        db.add(state)
    state.status, state.note, state.updated_at = payload.status, payload.note, datetime.now(timezone.utc)
    same_target = [s.id for s in db.query(Scan.id).filter(Scan.user_id == scan.user_id, Scan.target_label == scan.target_label).all()]
    db.query(Finding).filter(Finding.scan_id.in_(same_target), Finding.fingerprint == finding.fingerprint) \
        .update({Finding.status: payload.status}, synchronize_session=False)
    db.commit()
    db.refresh(finding)
    return finding_dict(finding, scan)


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

@reports_router.get("/summary")
def report_summary(scope: str = Query(default="mine", pattern="^(mine|org)$"), db: DBSession = Depends(get_db),
                   user: User = Depends(get_api_user)):
    if scope == "org" and (not user.is_org_admin or not user.org_id):
        raise HTTPException(status_code=403, detail="Only organization admins can view the organization summary.")
    return JSONResponse(json.loads(json.dumps(reports.summary(db, user, scope), default=str)))


@reports_router.get("/summary.{fmt}")
def report_summary_file(fmt: str, scope: str = Query(default="mine", pattern="^(mine|org)$"),
                        db: DBSession = Depends(get_db), user: User = Depends(get_api_user)):
    if fmt not in ("txt", "pdf"):
        raise HTTPException(status_code=404, detail="Unknown format.")
    if scope == "org" and (not user.is_org_admin or not user.org_id):
        raise HTTPException(status_code=403, detail="Only organization admins can view the organization summary.")
    text = reports.summary_text(reports.summary(db, user, scope), "OPSEC Scanner executive summary")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    if fmt == "txt":
        return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="opsec-summary-{stamp}.txt"'})
    return Response(reports.text_to_pdf(text), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="opsec-summary-{stamp}.pdf"'})


# --------------------------------------------------------------------------
# Identity graph, domain intelligence, rule catalog
# --------------------------------------------------------------------------

@intel_router.get("/identity/graph")
def get_identity_graph(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    return reports.identity_graph(db, user)


@intel_router.get("/intel/domains")
def domain_intel(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    out = []
    targets = db.query(MonitoredTarget).filter(MonitoredTarget.user_id == user.id, MonitoredTarget.kind == "domain").all()
    for t in targets:
        scan = db.get(Scan, t.last_scan_id) if t.last_scan_id else None
        stats = json.loads(scan.stats) if scan and scan.stats else {}
        out.append({"target_id": t.id, "domain": t.value, "verified": t.verified_at is not None,
                    "scan_id": scan.id if scan else None, "scanned_at": scan.completed_at if scan else None,
                    "intel": stats.get("intel", {}), "notes": stats.get("notes", []),
                    "open_findings": scan.total_findings if scan else 0})
    return out


@intel_router.get("/rules")
def rule_catalog(user: User = Depends(get_api_user)):
    return [{"id": rid, **meta} for rid, meta in sorted(svc.rule_meta().items())]


# --------------------------------------------------------------------------
# Integrations
# --------------------------------------------------------------------------

class IntegrationIn(BaseModel):
    kind: str = Field(pattern="^(slack|discord|telegram|webhook|github_issues|email)$")
    name: str = Field(min_length=1, max_length=80)
    config: dict = Field(default_factory=dict)
    min_severity: str = Field(default="HIGH", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    only_new: bool = True


class IntegrationPatch(BaseModel):
    enabled: bool | None = None
    min_severity: str | None = Field(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    only_new: bool | None = None


def _integration_out(i: Integration) -> dict:
    return {"id": i.id, "kind": i.kind, "name": i.name, "hint": i.config_hint, "min_severity": i.min_severity,
            "only_new": i.only_new, "enabled": i.enabled, "created_at": i.created_at,
            "last_sent_at": i.last_sent_at, "last_status": i.last_status}


def _own_integration(db, user, integration_id) -> Integration:
    row = db.get(Integration, integration_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Integration not found.")
    return row


@integrations_router.get("")
def list_integrations(db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    return [_integration_out(i) for i in db.query(Integration).filter(Integration.user_id == user.id).order_by(Integration.created_at).all()]


@integrations_router.post("", status_code=201)
def create_integration(payload: IntegrationIn, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    if db.query(Integration).filter(Integration.user_id == user.id).count() >= MAX_INTEGRATIONS:
        raise HTTPException(status_code=400, detail=f"At most {MAX_INTEGRATIONS} integrations.")
    try:
        config, hint = alerts.validate_config(payload.kind, payload.config)
    except (alerts.IntegrationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    row = Integration(user_id=user.id, kind=payload.kind, name=" ".join(payload.name.split()),
                      config_encrypted=alerts.encrypt_config(config), config_hint=hint,
                      min_severity=payload.min_severity, only_new=payload.only_new)
    db.add(row)
    db.commit()
    db.refresh(row)
    return _integration_out(row)


@integrations_router.patch("/{integration_id}")
def update_integration(integration_id: str, payload: IntegrationPatch, db: DBSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    row = _own_integration(db, user, integration_id)
    for field in ("enabled", "min_severity", "only_new"):
        value = getattr(payload, field)
        if value is not None:
            setattr(row, field, value)
    db.commit()
    return _integration_out(row)


@integrations_router.delete("/{integration_id}", status_code=204)
def delete_integration(integration_id: str, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    db.delete(_own_integration(db, user, integration_id))
    db.commit()
    return Response(status_code=204)


@integrations_router.post("/{integration_id}/test")
def test_integration(integration_id: str, db: DBSession = Depends(get_db), user: User = Depends(get_current_user)):
    row = _own_integration(db, user, integration_id)
    alert = {
        "title": "OPSEC Scanner test alert", "summary": "This destination is connected.",
        "lines": ["[INFO] test_alert ••••••••  — no real findings in this message"],
        "link": "", "payload": {"event": "opsec.test", "integration": row.name},
    }
    try:
        alerts.send(row.kind, alerts.decrypt_config(row.config_encrypted), alert, user.email)
        row.last_status = "test sent"
    except Exception as exc:  # noqa: BLE001
        row.last_status = f"test failed: {str(exc)[:150] if isinstance(exc, (alerts.IntegrationError, ValueError)) else type(exc).__name__}"
    row.last_sent_at = datetime.now(timezone.utc)
    db.commit()
    return _integration_out(row)

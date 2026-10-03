"""
Runs the collection modules for one verified target and stores the result
as a normal scan (source = "monitor"), so it shows up in the Operations
Center, findings explorer, diffs, exports and alerts like any other scan.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opsec_scanner.analysis.patterns import ScannedMatch
from opsec_scanner.models import RawFinding, SourceType

from opsec_platform.app import scan_service as svc
from opsec_platform.app.models import MonitoredTarget, Scan
from opsec_platform.app.osint import collectors

logger = logging.getLogger(__name__)

SCHEDULE_INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}

DIRECT_SOURCE = {
    "exposed_git_directory": SourceType.EXPOSURE_CHECK, "exposed_env_file": SourceType.EXPOSURE_CHECK,
    "exposed_backup_file": SourceType.EXPOSURE_CHECK, "exposed_ds_store": SourceType.EXPOSURE_CHECK,
    "exposed_server_status": SourceType.EXPOSURE_CHECK, "directory_listing": SourceType.WEB_CONTENT,
    "missing_security_headers": SourceType.WEB_CONTENT, "missing_spf": SourceType.DNS_RECORD,
    "permissive_spf": SourceType.DNS_RECORD, "missing_dmarc": SourceType.DNS_RECORD,
    "weak_dmarc_policy": SourceType.DNS_RECORD, "whois_registrant_exposed": SourceType.DNS_RECORD,
    "sensitive_subdomain": SourceType.CERT_TRANSPARENCY, "open_sensitive_port": SourceType.SERVICE_SCAN,
    "public_code_mention": SourceType.CODE_SEARCH, "breach_exposure": SourceType.BREACH_RECORD,
    "paste_exposure": SourceType.BREACH_RECORD,
}


def direct_to_matches(direct: list[collectors.DirectFinding]) -> list[ScannedMatch]:
    matches = []
    for d in direct:
        category, severity, _, _ = collectors.DIRECT_RULES[d.rule_id]
        raw = RawFinding(source_type=DIRECT_SOURCE.get(d.rule_id, SourceType.WEB_CONTENT),
                         raw_text=d.matched_text, context=d.context, origin=d.origin)
        matches.append(ScannedMatch(finding=raw, rule_id=d.rule_id, category=category,
                                    base_severity=severity, matched_text=d.matched_text))
    return matches


def owned_asset_scoring(scored):
    """Everything found on a verified target belongs to the user, so the
    identity multiplier is at least 1.0 (the generic 0.5 is for code of
    unknown ownership). A direct identity match keeps its 1.5 boost."""
    from opsec_scanner.scoring.risk_engine import EXPOSURE_WEIGHTS, _label_for_score

    for s in scored:
        if s.identity_confidence < 1.0:
            s.identity_confidence = 1.0
            s.identity_reason = "Found on an asset whose ownership you verified"
            score = min(10.0, s.match.base_severity * 1.0 * EXPOSURE_WEIGHTS[s.exposure_level])
            s.risk_score = round(score, 2)
            s.risk_label = _label_for_score(score)
    scored.sort(key=lambda s: s.risk_score, reverse=True)
    return scored


def collect(target: MonitoredTarget, verified_domains: list[str]) -> collectors.CollectorResult:
    result = collectors.CollectorResult()
    if target.kind == "domain":
        result.extend(collectors.exposure_checks(target.value))
        result.extend(collectors.crawl_site([f"https://{target.value}/"], verified_domains))
        result.extend(collectors.public_records(target.value))
        result.extend(collectors.github_code_search(target.value))
    elif target.kind == "url":
        result.extend(collectors.crawl_site([target.value], verified_domains, max_pages=20, max_depth=1))
    elif target.kind == "email":
        result.extend(collectors.breach_check(target.value))
        result.extend(collectors.github_code_search(target.value))
    elif target.kind == "github_handle":
        result.extend(collectors.github_handle(target.value))
        result.extend(_scan_handle_repos(result.intel.get("github", {}).get("repos", [])))
    return result


def _scan_handle_repos(repos: list[dict], limit: int = 3) -> collectors.CollectorResult:
    """Run the git engine over the most recently pushed non-fork repos."""
    from opsec_scanner.engines.git_engine import scan_git_repo

    result = collectors.CollectorResult()
    scanned = []
    for repo in [r for r in repos if not r.get("fork")][:limit]:
        try:
            url = svc.normalize_git_url(repo.get("url") or "")
        except svc.ScanInputError:
            continue
        workdir = Path(tempfile.mkdtemp(prefix="opsec-handle-"))
        try:
            svc.clone_repository(url, workdir / "repo", 50)
            raw = scan_git_repo(workdir / "repo", max_patch_commits=50)
            local = str(workdir / "repo")
            for finding in raw:
                if finding.origin.startswith(local):
                    finding.origin = url + finding.origin[len(local):]
            result.raw.extend(raw)
            scanned.append(url)
        except Exception as exc:
            result.notes.append(f"Could not scan {url}: {exc if isinstance(exc, svc.ScanInputError) else type(exc).__name__}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    result.intel["repos_scanned"] = scanned
    return result


def verified_domains_for(db, user_id: str) -> list[str]:
    rows = db.query(MonitoredTarget).filter(
        MonitoredTarget.user_id == user_id, MonitoredTarget.kind == "domain", MonitoredTarget.verified_at.isnot(None)
    ).all()
    return [r.value for r in rows]


def run_target_scan(scan_id: str, target_id: str, profile_data: dict, collect_fn=None) -> None:
    db = svc._session()
    try:
        scan = svc._mark_running(db, scan_id)
        target = db.get(MonitoredTarget, target_id)
        if scan is None or target is None:
            return
        if target.verified_at is None:
            svc._fail(db, scan_id, "Target is not verified.")
            return
        domains = verified_domains_for(db, target.user_id)
        result = (collect_fn or collect)(target, domains)
        scored = owned_asset_scoring(
            svc.analyze(result.raw, profile_data, public=True, extra_matches=direct_to_matches(result.direct))
        )
        stats = {
            "target_kind": target.kind,
            "raw_items_extracted": len(result.raw),
            "checks_flagged": len(result.direct),
            "intel": result.intel,
            "notes": sorted(set(result.notes))[:30],
        }
        scan = db.get(Scan, scan_id)
        svc.store_results(db, scan, svc.records_from_scored(scored), stats)
        target = db.get(MonitoredTarget, target_id)
        target.last_scan_id = scan_id
        target.last_scan_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:  # noqa: BLE001 — shown to the user as a failed scan
        logger.exception("Monitoring scan %s failed", scan_id)
        svc._fail(db, scan_id, f"Monitoring scan failed: {type(exc).__name__}")
    finally:
        db.close()


def create_target_scan(db, target: MonitoredTarget) -> Scan:
    """Creates the queued scan row. The caller submits run_target_scan once
    it has finished its own database work."""
    scan = Scan(user_id=target.user_id, org_id=target.org_id, source="monitor",
                target_label=f"{target.kind}:{target.value}"[:200], status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def next_run(schedule: str, now: datetime | None = None) -> datetime | None:
    interval = SCHEDULE_INTERVALS.get(schedule)
    return (now or datetime.now(timezone.utc)) + interval if interval else None

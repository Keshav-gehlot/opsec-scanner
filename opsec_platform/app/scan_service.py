"""
Scan execution and persistence for the web workspace.

Three ways a scan reaches the platform:

  json_import / cli_upload  A findings JSON produced by the CLI
                            (``--json-output`` or ``--upload-findings``).
  media_upload              Files uploaded in the browser, scanned here with
                            the same media engine the CLI uses.
  git_url                   A public HTTPS repository on an allow-listed
                            host, shallow-cloned into a temp dir and scanned
                            with the CLI's git engine.

Whatever the source, the platform never stores a raw matched value. Each
finding keeps a redacted preview plus a keyed fingerprint (HMAC) so scans of
the same target can be compared without the secret being recoverable from
the database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.config import get_settings
from opsec_platform.app.models import Finding, IdentityProfile, Scan, User

logger = logging.getLogger(__name__)

RISK_LABELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SAFE_METADATA_KEYS = ("commit_sha", "file", "change_type", "tag", "role")
ALLOWED_MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".heic", ".tiff", ".webp", ".pdf", ".docx", ".xlsx", ".pptx",
}
STALE_AFTER = timedelta(minutes=30)
_REPO_PATH_RE = re.compile(r"^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+){1,3}?(\.git)?/?$")


class ScanInputError(ValueError):
    """User-correctable problem with a scan request (bad URL, bad file)."""


# --------------------------------------------------------------------------
# Redaction and fingerprints
# --------------------------------------------------------------------------

def redact_preview(value: str) -> str:
    """Short, non-reversible preview of a matched value.

    Keeps a few leading characters (enough to recognise a key type such as
    ``AKIA`` or ``ghp_``) and the last two for values long enough that this
    reveals nothing usable. Short values are fully masked.
    """
    value = value.replace("\n", " ").strip()
    n = len(value)
    if n == 0:
        return ""
    if n < 8:
        return "•" * n
    lead = 4 if n >= 16 else 2
    tail = 2 if n >= 12 else 0
    hidden = min(n - lead - tail, 10)
    return value[:lead] + "•" * hidden + (value[-tail:] if tail else "")


def _fingerprint_key() -> bytes:
    settings = get_settings()
    explicit = os.environ.get("PLATFORM_FINGERPRINT_SECRET", "").strip()
    base = explicit or settings.jwt_secret or "opsec-dev-fingerprint"
    return hmac.new(base.encode("utf-8"), b"opsec-finding-fingerprint-v1", hashlib.sha256).digest()


def fingerprint(*parts: str) -> str:
    message = "\x1f".join(parts).encode("utf-8", "replace")
    return hmac.new(_fingerprint_key(), message, hashlib.sha256).hexdigest()[:32]


# --------------------------------------------------------------------------
# Identity profile
# --------------------------------------------------------------------------

PROFILE_LIST_FIELDS = ("aliases", "emails", "domains", "github_handles")


def default_profile_data(user: User) -> dict:
    local = user.email.split("@", 1)[0]
    return {
        "name": user.display_name or local,
        "aliases": [local] if local != (user.display_name or local) else [],
        "emails": [user.email],
        "domains": [],
        "github_handles": [],
        "home_coordinates": None,
    }


def load_profile_data(db: DBSession, user: User) -> dict:
    row = db.get(IdentityProfile, user.id)
    if row is None:
        return default_profile_data(user)
    try:
        data = json.loads(row.data or "{}")
    except json.JSONDecodeError:
        return default_profile_data(user)
    merged = default_profile_data(user)
    merged.update({k: v for k, v in data.items() if k in merged})
    return merged


def save_profile_data(db: DBSession, user: User, data: dict) -> dict:
    row = db.get(IdentityProfile, user.id)
    payload = json.dumps(data)
    if row is None:
        db.add(IdentityProfile(user_id=user.id, data=payload, updated_at=datetime.now(timezone.utc)))
    else:
        row.data = payload
        row.updated_at = datetime.now(timezone.utc)
    db.commit()
    return data


def to_target_profile(data: dict):
    from opsec_scanner.config import TargetProfile

    coords = data.get("home_coordinates")
    return TargetProfile(
        name=data.get("name") or "unknown",
        aliases=list(data.get("aliases") or []),
        emails=list(data.get("emails") or []),
        domains=list(data.get("domains") or []),
        github_handles=list(data.get("github_handles") or []),
        home_coordinates=tuple(coords) if coords else None,
    )


# --------------------------------------------------------------------------
# Analysis pipeline (shared with the CLI)
# --------------------------------------------------------------------------

def rules_status() -> dict:
    """Whether the detection rule file can be loaded in this deployment.
    A missing rule file would make every scan report "clean", so /health
    surfaces it instead of letting scans silently succeed."""
    try:
        from opsec_scanner.analysis.patterns import DEFAULT_RULES_PATH, load_rules

        if not DEFAULT_RULES_PATH.exists():
            return {"ok": False, "rules": 0, "detail": "rules/patterns.yaml not found next to the package"}
        return {"ok": True, "rules": len(load_rules())}
    except BaseException as exc:  # load_rules exits on corrupt YAML
        return {"ok": False, "rules": 0, "detail": type(exc).__name__}


def analyze(raw_findings, profile_data: dict, public: bool = False):
    from opsec_scanner.analysis.patterns import load_rules, scan_findings
    from opsec_scanner.scoring.risk_engine import ExposureLevel, deduplicate_findings, score_findings

    status = rules_status()
    if not status["ok"]:
        raise RuntimeError("Detection rules are unavailable on this server.")
    matches = scan_findings(raw_findings, load_rules())
    exposure = ExposureLevel.PUBLIC_REACHABLE if public else None
    scored = score_findings(matches, to_target_profile(profile_data), exposure_override=exposure)
    return deduplicate_findings(scored)


@dataclass
class FindingRecord:
    fingerprint: str
    risk_score: float
    risk_label: str
    rule_id: str
    category: str
    preview: str
    matched_length: int
    base_severity: float | None = None
    entropy_score: float | None = None
    identity_confidence: float | None = None
    identity_reason: str | None = None
    exposure_level: str | None = None
    source_type: str | None = None
    origin: str | None = None
    context: str | None = None
    occurrence_count: int = 1


def records_from_scored(scored) -> list[FindingRecord]:
    records = []
    for s in scored:
        f = s.match.finding
        records.append(FindingRecord(
            fingerprint=fingerprint(s.match.rule_id, f.origin, s.match.matched_text),
            risk_score=float(s.risk_score),
            risk_label=s.risk_label,
            rule_id=s.match.rule_id,
            category=s.match.category,
            preview=redact_preview(s.match.matched_text),
            matched_length=len(s.match.matched_text),
            base_severity=s.match.base_severity,
            entropy_score=s.match.entropy_score,
            identity_confidence=s.identity_confidence,
            identity_reason=s.identity_reason,
            exposure_level=s.exposure_level.value,
            source_type=f.source_type.value,
            origin=f.origin[:1000],
            context=_safe_context(f.context, f.metadata),
            occurrence_count=int(f.metadata.get("occurrence_count", 1)),
        ))
    return records


def _safe_context(context: str, metadata: dict | None) -> str:
    extra = {k: metadata[k] for k in SAFE_METADATA_KEYS if metadata and metadata.get(k)}
    text = context or ""
    if extra and not text:
        text = ", ".join(f"{k}={v}" for k, v in extra.items())
    return text[:1000]


_IMPORT_PLACEHOLDER = "█"


def _num(value, default=None):
    try:
        if value is None:
            return default
        number = float(value)
        return number if number == number else default  # NaN guard
    except (TypeError, ValueError):
        return default


def records_from_export(payload: dict, max_findings: int) -> list[FindingRecord]:
    """Validate and convert a CLI JSON export (json_export.export_json)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise ScanInputError("Not an OPSEC Scanner findings export: expected an object with a 'findings' list.")
    findings = payload["findings"]
    if len(findings) > max_findings:
        raise ScanInputError(f"Too many findings in one upload (limit {max_findings}).")

    records = []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ScanInputError(f"Finding #{index + 1} is not an object.")
        rule_id = str(item.get("rule_id") or "").strip()[:120]
        label = str(item.get("risk_label") or "").upper()
        score = _num(item.get("risk_score"))
        if not rule_id or label not in RISK_LABELS or score is None:
            raise ScanInputError(f"Finding #{index + 1} is missing rule_id, risk_label or risk_score.")
        matched = str(item.get("matched_text") or "")
        origin = str(item.get("origin") or "")[:1000]
        context = str(item.get("context") or "")[:1000]
        redacted = (not matched) or set(matched) <= {_IMPORT_PLACEHOLDER}
        length = int(_num(item.get("matched_text_length"), len(matched)) or 0)
        if redacted:
            fp = fingerprint(rule_id, origin, context, str(length), "redacted")
            preview = "•" * min(max(length, 6), 16)
        else:
            fp = fingerprint(rule_id, origin, matched)
            preview = redact_preview(matched)
            length = len(matched)
        records.append(FindingRecord(
            fingerprint=fp,
            risk_score=max(0.0, min(10.0, score)),
            risk_label=label,
            rule_id=rule_id,
            category=str(item.get("category") or "uncategorized")[:120],
            preview=preview,
            matched_length=length,
            base_severity=_num(item.get("base_severity")),
            entropy_score=_num(item.get("entropy_score")),
            identity_confidence=_num(item.get("identity_confidence")),
            identity_reason=str(item.get("identity_reason") or "")[:500] or None,
            exposure_level=str(item.get("exposure_level") or "")[:40] or None,
            source_type=str(item.get("source_type") or "")[:40] or None,
            origin=origin,
            context=context,
            occurrence_count=max(1, int(_num(item.get("occurrence_count"), 1) or 1)),
        ))
    records.sort(key=lambda r: r.risk_score, reverse=True)
    return records


def store_results(db: DBSession, scan: Scan, records: list[FindingRecord], stats: dict | None = None) -> Scan:
    for record in records:
        db.add(Finding(scan_id=scan.id, **record.__dict__))
    counts = {label: 0 for label in RISK_LABELS}
    for record in records:
        counts[record.risk_label] = counts.get(record.risk_label, 0) + 1
    scan.total_findings = len(records)
    scan.critical_count = counts["CRITICAL"]
    scan.high_count = counts["HIGH"]
    scan.medium_count = counts["MEDIUM"]
    scan.low_count = counts["LOW"]
    scan.max_risk_score = max((r.risk_score for r in records), default=0.0)
    scan.stats = json.dumps(stats or {}, default=str)
    scan.status = "completed"
    scan.error = None
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


# --------------------------------------------------------------------------
# Background execution
# --------------------------------------------------------------------------

_executor: ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()
_futures: set[Future] = set()


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _executor_lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=max(1, get_settings().scan_max_concurrent), thread_name_prefix="opsec-scan"
            )
        return _executor


def submit(fn, *args) -> None:
    future = _get_executor().submit(fn, *args)
    _futures.add(future)
    future.add_done_callback(_futures.discard)


def wait_for_idle(timeout: float = 60.0) -> None:
    """Block until queued scan jobs finish (used by tests and shutdown)."""
    from concurrent.futures import wait

    pending = list(_futures)
    if pending:
        wait(pending, timeout=timeout)


def _session():
    from opsec_platform.app import dependencies

    if dependencies._SessionLocal is None:
        dependencies.configure_db()
    return dependencies._SessionLocal()


def _mark_running(db: DBSession, scan_id: str) -> Scan | None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        return None
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    db.commit()
    return scan


def _fail(db: DBSession, scan_id: str, message: str) -> None:
    db.rollback()
    scan = db.get(Scan, scan_id)
    if scan is not None:
        scan.status = "failed"
        scan.error = message[:500]
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()


def recover_stale_scans(db: DBSession) -> int:
    """Jobs run in-process; a restart orphans anything queued or running.
    Mark jobs older than STALE_AFTER as failed so the UI does not spin
    forever."""
    cutoff = datetime.now(timezone.utc) - STALE_AFTER
    changed = 0
    for scan in db.query(Scan).filter(Scan.status.in_(("queued", "running"))).all():
        created = scan.created_at if scan.created_at.tzinfo else scan.created_at.replace(tzinfo=timezone.utc)
        if created < cutoff:
            scan.status = "failed"
            scan.error = "The scan was interrupted (server restart or timeout). Run it again."
            scan.completed_at = datetime.now(timezone.utc)
            changed += 1
    if changed:
        db.commit()
    return changed


# --------------------------------------------------------------------------
# Media scans
# --------------------------------------------------------------------------

def safe_upload_name(name: str, index: int) -> str:
    base = Path(name or "").name
    ext = Path(base).suffix.lower()
    if ext not in ALLOWED_MEDIA_EXTENSIONS:
        raise ScanInputError(
            f"Unsupported file type '{ext or base}'. Allowed: " + ", ".join(sorted(ALLOWED_MEDIA_EXTENSIONS))
        )
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(base).stem)[:80] or f"file{index}"
    return f"{index:02d}_{stem}{ext}"


def run_media_scan(scan_id: str, files: list[tuple[str, bytes]], profile_data: dict) -> None:
    db = _session()
    workdir = Path(tempfile.mkdtemp(prefix="opsec-media-"))
    try:
        if _mark_running(db, scan_id) is None:
            return
        for name, content in files:
            (workdir / name).write_bytes(content)

        from opsec_scanner.engines.media_engine import scan_media_dir

        raw = scan_media_dir(workdir, max_workers=2)
        prefix = str(workdir) + os.sep
        for finding in raw:
            if finding.origin.startswith(prefix):
                finding.origin = finding.origin[len(prefix):]
        scored = analyze(raw, profile_data, public=False)
        notes = sorted({f.raw_text for f in raw if f.raw_text.startswith("[") and "skipping" in f.raw_text})
        stats = {"media_files_scanned": len(files), "raw_items_extracted": len(raw), "notes": notes}
        store_results(db, db.get(Scan, scan_id), records_from_scored(scored), stats)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a failed scan
        logger.exception("Media scan %s failed", scan_id)
        _fail(db, scan_id, f"Media scan failed: {type(exc).__name__}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        db.close()


# --------------------------------------------------------------------------
# Git URL scans
# --------------------------------------------------------------------------

def normalize_git_url(url: str) -> str:
    """Accept only https://<allow-listed host>/<owner>/<repo>[.git].

    No credentials, ports, query strings or other schemes: the server
    clones on behalf of the user, so anything that could point the clone at
    an internal address or smuggle options to git is rejected."""
    settings = get_settings()
    url = (url or "").strip()
    if len(url) > 300:
        raise ScanInputError("Repository URL is too long.")
    if url.startswith("-"):
        raise ScanInputError("Invalid repository URL.")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ScanInputError("Only https:// repository URLs are supported.")
    if parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment or parsed.params:
        raise ScanInputError("Repository URL must not contain credentials, a port, a query or a fragment.")
    host = (parsed.hostname or "").lower()
    if host not in settings.scan_git_hosts:
        raise ScanInputError("Repository host is not allowed. Supported hosts: " + ", ".join(settings.scan_git_hosts))
    if not _REPO_PATH_RE.match(parsed.path) or ".." in parsed.path:
        raise ScanInputError("Repository URL must look like https://host/owner/repo.")
    path = parsed.path.rstrip("/")
    return f"https://{host}{path}"


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def clone_repository(url: str, dest: Path, depth: int) -> None:
    settings = get_settings()
    if shutil.which("git") is None:
        raise RuntimeError("git is not installed on this server.")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(dest.parent),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_ALLOW_PROTOCOL": "https",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    # Keep the host's outbound proxy / CA settings (corporate egress), but
    # nothing else from the server environment reaches git.
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
                 "GIT_SSL_CAINFO", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    command = [
        "git",
        "-c", "http.followRedirects=false",
        "-c", "credential.helper=",
        "-c", "core.askPass=/bin/true",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "clone", "--quiet", "--no-checkout", "--no-tags", "--no-single-branch",
        "--depth", str(depth),
        "--", url, str(dest),
    ]
    try:
        result = subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=settings.scan_git_timeout_seconds
        )
    except subprocess.TimeoutExpired:
        raise ScanInputError("Cloning took too long. Try a smaller depth or a smaller repository.") from None
    if result.returncode != 0:
        stderr = (result.stderr or "").lower()
        if "not found" in stderr or "could not read username" in stderr or "authentication" in stderr:
            raise ScanInputError("Repository not found or not public.")
        if "redirect" in stderr:
            raise ScanInputError("The repository URL redirects (renamed or moved). Use its current URL.")
        raise ScanInputError("git clone failed for this repository.")
    if _dir_size(dest) > settings.scan_git_max_mb * 1024 * 1024:
        raise ScanInputError(f"Repository is larger than the {settings.scan_git_max_mb} MB limit for web scans.")


def run_git_scan(scan_id: str, url: str, depth: int, profile_data: dict) -> None:
    db = _session()
    workdir = Path(tempfile.mkdtemp(prefix="opsec-git-"))
    try:
        if _mark_running(db, scan_id) is None:
            return
        repo_dir = workdir / "repo"
        clone_repository(url, repo_dir, depth)

        from opsec_scanner.engines.git_engine import scan_git_repo

        stats: dict = {}
        raw = scan_git_repo(repo_dir, max_patch_commits=depth, stats=stats)
        local = str(repo_dir)
        for finding in raw:
            if finding.origin.startswith(local):
                finding.origin = url + finding.origin[len(local):]
        scored = analyze(raw, profile_data, public=True)
        stats.update({"repository": url, "clone_depth": depth, "raw_items_extracted": len(raw)})
        store_results(db, db.get(Scan, scan_id), records_from_scored(scored), stats)
    except ScanInputError as exc:
        _fail(db, scan_id, str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Git scan %s failed", scan_id)
        _fail(db, scan_id, f"Repository scan failed: {type(exc).__name__}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        db.close()


# --------------------------------------------------------------------------
# Capabilities
# --------------------------------------------------------------------------

def capabilities() -> dict:
    settings = get_settings()
    return {
        "web_scans_enabled": settings.web_scans_enabled,
        "git_available": shutil.which("git") is not None,
        "exiftool_available": shutil.which("exiftool") is not None,
        "ocr_available": shutil.which("tesseract") is not None,
        "rules": rules_status(),
        "allowed_git_hosts": list(settings.scan_git_hosts),
        "limits": {
            "media_max_files": settings.scan_media_max_files,
            "media_max_file_mb": settings.scan_media_max_file_mb,
            "media_max_total_mb": settings.scan_media_max_total_mb,
            "import_max_mb": settings.scan_import_max_mb,
            "import_max_findings": settings.scan_import_max_findings,
            "git_default_depth": settings.scan_git_default_depth,
            "git_max_depth": settings.scan_git_max_depth,
            "git_max_mb": settings.scan_git_max_mb,
            "daily_scans_per_user": settings.scan_daily_limit,
        },
        "media_extensions": sorted(ALLOWED_MEDIA_EXTENSIONS),
    }

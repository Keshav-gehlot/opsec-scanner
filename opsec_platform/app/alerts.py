"""
Alert destinations (Slack, Discord, Telegram, generic JSON webhook for
SIEM/SOAR, GitHub Issues, email) and dispatch after a scan completes.

Destination secrets (webhook URLs, bot tokens, API tokens) are encrypted at
rest with Fernet; the API only ever returns a short non-secret hint.
Alert content uses the same redacted previews as the UI: raw secret values
never leave the platform.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

from opsec_platform.app.config import get_settings
from opsec_platform.app.models import Finding, Integration, Scan, User
from opsec_platform.app.osint import net

logger = logging.getLogger(__name__)

KINDS = ("slack", "discord", "telegram", "webhook", "github_issues", "email")
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class IntegrationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def _fernet() -> Fernet:
    secret = os.environ.get("PLATFORM_INTEGRATIONS_KEY", "").strip() or get_settings().jwt_secret or "opsec-dev-integrations"
    key = hashlib.sha256(("opsec-integrations-v1:" + secret).encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_config(config: dict) -> str:
    return _fernet().encrypt(json.dumps(config).encode("utf-8")).decode("ascii")


def decrypt_config(blob: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(blob.encode("ascii")))
    except (InvalidToken, ValueError):
        raise IntegrationError("Stored configuration can no longer be decrypted (key changed). Re-create this integration.")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _https_host(url: str) -> str:
    parsed = urlparse(url or "")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise IntegrationError("Use an https:// URL without credentials.")
    return parsed.hostname.lower()


def validate_config(kind: str, config: dict) -> tuple[dict, str]:
    """Returns (clean_config, hint). Raises IntegrationError."""
    config = {k: (v.strip() if isinstance(v, str) else v) for k, v in (config or {}).items()}
    if kind == "slack":
        url = config.get("webhook_url", "")
        if _https_host(url) != "hooks.slack.com" or not urlparse(url).path.startswith("/services/"):
            raise IntegrationError("Slack needs an incoming webhook URL (https://hooks.slack.com/services/...).")
        return {"webhook_url": url}, "hooks.slack.com/…" + url[-4:]
    if kind == "discord":
        url = config.get("webhook_url", "")
        if _https_host(url) not in ("discord.com", "discordapp.com") or "/api/webhooks/" not in urlparse(url).path:
            raise IntegrationError("Discord needs a channel webhook URL (https://discord.com/api/webhooks/...).")
        return {"webhook_url": url}, "discord.com/…" + url[-4:]
    if kind == "telegram":
        token, chat = config.get("bot_token", ""), str(config.get("chat_id", ""))
        if not re.fullmatch(r"\d{6,12}:[A-Za-z0-9_-]{30,}", token) or not re.fullmatch(r"-?\d{3,20}|@[A-Za-z0-9_]{5,32}", chat):
            raise IntegrationError("Telegram needs a bot token (123456:ABC...) and a chat id.")
        return {"bot_token": token, "chat_id": chat}, f"chat {chat}"
    if kind == "webhook":
        url = config.get("url", "")
        host = _https_host(url)
        net.validate_url(url)
        secret = config.get("secret") or ""
        if len(secret) > 200:
            raise IntegrationError("Signing secret is too long.")
        return {"url": url, "secret": secret}, host
    if kind == "github_issues":
        repo, token = config.get("repo", ""), config.get("token", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or len(token) < 20:
            raise IntegrationError("GitHub Issues needs owner/repo and a token with issues:write.")
        return {"repo": repo, "token": token}, repo
    if kind == "email":
        if not os.environ.get("PLATFORM_SMTP_HOST"):
            raise IntegrationError("Email alerts need PLATFORM_SMTP_HOST (and related settings) on the server.")
        return {}, "your account email"
    raise IntegrationError("Unknown integration type.")


# ---------------------------------------------------------------------------
# Message building and delivery
# ---------------------------------------------------------------------------

def build_alert(scan: Scan, findings: list[Finding], base_url: str) -> dict:
    counts = {label: sum(1 for f in findings if f.risk_label == label) for label in SEVERITY_ORDER}
    top = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:10]
    link = f"{base_url.rstrip('/')}/dashboard#/scan/{scan.id}"
    summary = ", ".join(f"{n} {label.lower()}" for label, n in sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]) if n)
    lines = [f"[{f.risk_label}] {f.rule_id} {f.preview} — {(f.origin or '')[:120]}" for f in top]
    return {
        "title": f"OPSEC Scanner: {len(findings)} finding(s) on {scan.target_label}",
        "summary": summary,
        "lines": lines,
        "link": link,
        "payload": {
            "event": "opsec.scan.findings",
            "scan_id": scan.id,
            "target": scan.target_label,
            "source": scan.source,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "counts": counts,
            "findings": [
                {"rule_id": f.rule_id, "risk_label": f.risk_label, "risk_score": f.risk_score, "category": f.category,
                 "preview": f.preview, "origin": f.origin, "fingerprint": f.fingerprint}
                for f in top
            ],
            "link": link,
        },
    }


def _text(alert: dict) -> str:
    return "\n".join([alert["title"], alert["summary"], "", *alert["lines"], "", alert["link"]])


def send(kind: str, config: dict, alert: dict, user_email: str, post=net.safe_request, api_get=None) -> None:
    if kind == "slack":
        response = post("POST", config["webhook_url"], json_body={"text": _text(alert)}, timeout=10)
    elif kind == "discord":
        response = post("POST", config["webhook_url"], json_body={"content": _text(alert)[:1900]}, timeout=10)
    elif kind == "telegram":
        response = post("POST", f"https://api.telegram.org/bot{config['bot_token']}/sendMessage",
                        json_body={"chat_id": config["chat_id"], "text": _text(alert)[:4000], "disable_web_page_preview": True},
                        timeout=10)
    elif kind == "webhook":
        body = json.dumps(alert["payload"]).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if config.get("secret"):
            headers["X-OPSEC-Signature"] = "sha256=" + hmac.new(config["secret"].encode(), body, hashlib.sha256).hexdigest()
        response = post("POST", config["url"], data=body, headers=headers, timeout=10)
    elif kind == "github_issues":
        response = post("POST", f"https://api.github.com/repos/{config['repo']}/issues",
                        json_body={"title": alert["title"][:250], "body": "```\n" + _text(alert)[:60000] + "\n```",
                                   "labels": ["opsec-scanner"]},
                        headers={"Authorization": f"Bearer {config['token']}", "Accept": "application/vnd.github+json"},
                        timeout=15)
    elif kind == "email":
        _send_email(user_email, alert)
        return
    else:
        raise IntegrationError("Unknown integration type.")
    if response.status_code >= 300:
        raise IntegrationError(f"Destination returned HTTP {response.status_code}.")


def _send_email(to: str, alert: dict) -> None:
    host = os.environ.get("PLATFORM_SMTP_HOST", "")
    if not host:
        raise IntegrationError("SMTP is not configured.")
    message = EmailMessage()
    message["Subject"] = alert["title"]
    message["From"] = os.environ.get("PLATFORM_SMTP_FROM", "opsec-scanner@localhost")
    message["To"] = to
    message.set_content(_text(alert))
    port = int(os.environ.get("PLATFORM_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if os.environ.get("PLATFORM_SMTP_STARTTLS", "true").lower() != "false":
            smtp.starttls()
        user = os.environ.get("PLATFORM_SMTP_USER")
        if user:
            smtp.login(user, os.environ.get("PLATFORM_SMTP_PASSWORD", ""))
        smtp.send_message(message)


def findings_to_alert(db, scan: Scan, integration: Integration) -> list[Finding]:
    from opsec_platform.app.scan_routes import _previous_scan

    threshold = SEVERITY_ORDER.get(integration.min_severity, 2)
    rows = [
        f for f in db.query(Finding).filter(Finding.scan_id == scan.id).all()
        if SEVERITY_ORDER.get(f.risk_label, 0) >= threshold and f.status not in ("resolved", "suppressed", "false_positive")
    ]
    if integration.only_new:
        previous = _previous_scan(db, scan)
        if previous is not None:
            seen = {fp for (fp,) in db.query(Finding.fingerprint).filter(Finding.scan_id == previous.id).all()}
            rows = [f for f in rows if f.fingerprint not in seen]
    return rows


def dispatch_for_scan(scan_id: str, sender=None) -> dict:
    from opsec_platform.app import scan_service as svc

    db = svc._session()
    results = {}
    try:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "completed":
            return results
        user = db.get(User, scan.user_id)
        integrations = db.query(Integration).filter(Integration.user_id == scan.user_id, Integration.enabled.is_(True)).all()
        for integration in integrations:
            rows = findings_to_alert(db, scan, integration)
            if not rows:
                continue
            try:
                alert = build_alert(scan, rows, get_settings().base_url)
                (sender or send)(integration.kind, decrypt_config(integration.config_encrypted), alert, user.email if user else "")
                integration.last_status = f"sent {len(rows)} finding(s)"
            except Exception as exc:  # noqa: BLE001
                integration.last_status = f"failed: {str(exc)[:150] if isinstance(exc, IntegrationError) else type(exc).__name__}"
                logger.warning("Alert via %s failed for scan %s: %s", integration.kind, scan_id, type(exc).__name__)
            integration.last_sent_at = datetime.now(timezone.utc)
            results[integration.id] = integration.last_status
        db.commit()
    finally:
        db.close()
    return results

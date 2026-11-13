"""
Optional CLI -> platform activity reporting.

The scanner remains local-first and offline by default — nothing here
runs unless the person running the CLI explicitly passes
--report-activity with a platform URL and a bearer token. This module
is the one deliberate exception to "the CLI never phones home," and
it's opt-in specifically so that exception is always a conscious choice,
never a default.

A token is obtained by logging into the platform separately (e.g. via
curl against /auth/login, or a future dedicated CLI login helper) —
this module doesn't implement an interactive login flow itself, just
the reporting call once you already have a token.
"""

from __future__ import annotations

from urllib.parse import urlparse

from opsec_scanner.scoring.risk_engine import ScoredFinding


def build_scan_summary(scored: list[ScoredFinding], target_label: str) -> str:
    from collections import Counter
    counts = Counter(s.risk_label for s in scored)
    parts = [f"{counts[label]} {label}" for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(label)]
    summary = ", ".join(parts) if parts else "0 findings"
    return f"{target_label}: {summary}"


class ActivityReportError(Exception):
    """Raised for any failure reporting activity to the platform —
    network error, auth failure, unexpected response. Always caught at
    the CLI layer and turned into a warning, never allowed to fail the
    scan itself; the local reports are the CLI's actual job, and must
    still be written even if the platform is unreachable."""


def _validate_platform_url(platform_url: str) -> None:
    parsed = urlparse(platform_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ActivityReportError("Platform URL must be an absolute http(s) URL.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ActivityReportError("Refusing to send the platform bearer token over plain HTTP. Use HTTPS (HTTP is allowed only for local development).")


def report_scan_activity(
    platform_url: str,
    token: str,
    scored: list[ScoredFinding],
    target_label: str,
    http_client=None,
) -> dict:
    """
    POSTs a scan summary to {platform_url}/activity/report-scan.

    http_client, if given, is used instead of creating a real
    httpx.Client — lets callers (e.g. tests) supply their own client
    configuration without this function needing to know why.
    """
    _validate_platform_url(platform_url)

    try:
        import httpx
    except ImportError as e:
        raise ActivityReportError(
            "Reporting activity to a platform requires httpx: pip install httpx."
        ) from e

    summary = build_scan_summary(scored, target_label)
    owns_client = http_client is None
    client = http_client or httpx.Client(base_url=platform_url, timeout=10.0)

    try:
        response = client.post(
            "/activity/report-scan",
            params={"detail": summary},
            headers={"Authorization": f"Bearer {token}"},
        )
    except Exception as e:
        raise ActivityReportError(f"Could not reach the platform at {platform_url}: {e}") from e
    finally:
        if owns_client:
            client.close()

    if response.status_code == 401:
        raise ActivityReportError("Platform rejected the token — it may be expired or revoked. Log in again to get a new one.")
    if response.status_code >= 400:
        raise ActivityReportError(f"Platform returned {response.status_code}: {response.text}")

    return response.json()


def build_upload_payload(scored: list[ScoredFinding], target_label: str, scan_stats: dict | None = None) -> dict:
    """The redacted JSON export shape (json_export.export_json with
    reveal=False) plus the target label and scan-scope stats. Matched values
    are never included: the platform only ever receives the redaction
    placeholder, the value's length, and where it was found."""
    from datetime import datetime, timezone

    from opsec_scanner.output.json_export import _REDACTED_PLACEHOLDER

    safe_metadata_keys = ("commit_sha", "file", "change_type", "tag", "role")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "redacted": True,
        "target_label": target_label,
        "scan_stats": {k: v for k, v in (scan_stats or {}).items() if isinstance(v, (int, float, str))},
        "total_findings": len(scored),
        "findings": [
            {
                "risk_score": s.risk_score,
                "risk_label": s.risk_label,
                "rule_id": s.match.rule_id,
                "category": s.match.category,
                "matched_text": _REDACTED_PLACEHOLDER,
                "matched_text_length": len(s.match.matched_text),
                "base_severity": s.match.base_severity,
                "entropy_score": s.match.entropy_score,
                "identity_confidence": s.identity_confidence,
                "identity_reason": s.identity_reason,
                "exposure_level": s.exposure_level.value,
                "source_type": s.match.finding.source_type.value,
                "origin": s.match.finding.origin,
                "context": s.match.finding.context,
                "occurrence_count": s.match.finding.metadata.get("occurrence_count", 1),
                "metadata": {k: v for k, v in s.match.finding.metadata.items() if k in safe_metadata_keys},
            }
            for s in scored
        ],
    }


def upload_findings(
    platform_url: str,
    token: str,
    scored: list[ScoredFinding],
    target_label: str,
    scan_stats: dict | None = None,
    http_client=None,
) -> dict:
    """POSTs redacted findings to {platform_url}/scans/import so they show
    up in the web workspace (Operations Center, findings explorer, diffs).
    Opt-in via --upload-findings; same URL/token rules as activity
    reporting. Returns the created scan record."""
    _validate_platform_url(platform_url)
    try:
        import httpx
    except ImportError as e:
        raise ActivityReportError("Uploading findings requires httpx: pip install httpx.") from e

    payload = build_upload_payload(scored, target_label, scan_stats)
    owns_client = http_client is None
    client = http_client or httpx.Client(base_url=platform_url, timeout=30.0)
    try:
        response = client.post(
            "/scans/import",
            params={"label": target_label[:120]},
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
    except Exception as e:
        raise ActivityReportError(f"Could not reach the platform at {platform_url}: {e}") from e
    finally:
        if owns_client:
            client.close()

    if response.status_code == 401:
        raise ActivityReportError("Platform rejected the token — it may be expired or revoked. Create a new access token.")
    if response.status_code >= 400:
        raise ActivityReportError(f"Platform returned {response.status_code}: {response.text[:300]}")
    return response.json()


def session_token_from_set_cookie(set_cookie: str, cookie_name: str = "opsec_session") -> str | None:
    """Pull the session cookie's value out of a Set-Cookie header."""
    marker = cookie_name + "="
    if marker not in set_cookie:
        return None
    return set_cookie.split(marker, 1)[1].split(";", 1)[0] or None


def create_cli_token(platform_url: str, email: str, password: str, token_name: str,
                     expires_in_days: int = 90, http_client=None) -> dict:
    """Sign in with email + password, mint a CLI access token (opsec_pat_...),
    then sign the temporary browser session out again.

    The access token is what --report-activity / --upload-findings should
    use: it is scoped to scan uploads and activity reports, expires, and can
    be revoked from the workspace, whereas a session token can do anything
    the account can. Returns the /auth/tokens response ({"token", ...}).
    """
    _validate_platform_url(platform_url)
    try:
        import httpx
    except ImportError as e:
        raise ActivityReportError("Signing in to the platform requires httpx: pip install httpx.") from e

    owns_client = http_client is None
    client = http_client or httpx.Client(base_url=platform_url, timeout=30.0)
    try:
        try:
            login = client.post("/auth/login", json={"email": email, "password": password})
        except Exception as e:
            raise ActivityReportError(f"Could not reach the platform at {platform_url}: {e}") from e
        if login.status_code == 401:
            raise ActivityReportError(
                "Email or password is incorrect. Accounts that only use Google/GitHub/Microsoft/Apple "
                "sign-in have no password: create a token in the web workspace (CLI access tokens) instead."
            )
        if login.status_code == 429:
            raise ActivityReportError("Too many failed sign-ins. Wait a few minutes and try again.")
        if login.status_code >= 400:
            raise ActivityReportError(f"Sign-in failed ({login.status_code}): {login.text[:200]}")

        session = session_token_from_set_cookie(login.headers.get("set-cookie", ""))
        if not session:
            raise ActivityReportError("Platform did not return a session after sign-in.")
        auth = {"Authorization": f"Bearer {session}"}
        try:
            created = client.post("/auth/tokens", json={"name": token_name, "expires_in_days": expires_in_days}, headers=auth)
        finally:
            try:
                client.post("/auth/logout", headers=auth)
            except Exception:
                pass  # the session expires on its own; never mask the real outcome
        if created.status_code >= 400:
            raise ActivityReportError(f"Could not create an access token ({created.status_code}): {created.text[:200]}")
        return created.json()
    finally:
        if owns_client:
            client.close()

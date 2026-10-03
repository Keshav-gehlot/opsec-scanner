"""
Tests the CLI -> platform activity-reporting client against the real
platform FastAPI app.

report_scan_activity uses a synchronous httpx.Client, which is the
right choice for a CLI tool — no reason to drag in asyncio for a single
outbound POST. httpx's ASGITransport only implements the async request
path, so it doesn't fit a sync client without either an awkward
asyncio.run() wrapper or redesigning the client around async — not
worth compromising the CLI-facing design just for test convenience.
Instead, these tests run a real ephemeral platform server in a
background thread on a free port and hit it over real loopback HTTP —
still fully local and fast, but genuinely exercising both real client
and real server code, not a mock standing in for either side.
"""

import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

PLATFORM_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PLATFORM_ROOT))

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")

from opsec_scanner.output.platform_client import (
    build_scan_summary, report_scan_activity, ActivityReportError,
)
from opsec_scanner.analysis.patterns import ScannedMatch
from opsec_scanner.scoring.risk_engine import score_findings, ExposureLevel
from opsec_scanner.config import TargetProfile
from opsec_scanner.models import RawFinding, SourceType


def _scored_findings():
    profile = TargetProfile(name="Test")
    f1 = RawFinding(source_type=SourceType.GIT_PATCH, raw_text="AKIATEST0000000000A", origin="repo")
    m1 = ScannedMatch(finding=f1, rule_id="aws_access_key", category="credentials", base_severity=9.5, matched_text="AKIATEST0000000000A")
    f2 = RawFinding(source_type=SourceType.GIT_PATCH, raw_text="db.internal", origin="repo")
    m2 = ScannedMatch(finding=f2, rule_id="internal_hostname", category="infrastructure", base_severity=7.5, matched_text="db.internal")
    return score_findings([m1, m2], profile, exposure_override=ExposureLevel.PUBLIC_REACHABLE)


def test_build_scan_summary_formats_counts_by_label():
    scored = _scored_findings()
    summary = build_scan_summary(scored, "my-repo")
    assert summary.startswith("my-repo:")
    assert any(label in summary for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))


def test_build_scan_summary_handles_zero_findings():
    summary = build_scan_summary([], "clean-repo")
    assert summary == "clean-repo: 0 findings"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_platform_url():
    """Starts a real platform server on a free local port in a background
    thread, yields its base URL, and shuts it down afterward."""
    import uvicorn

    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    os.environ["PLATFORM_DATABASE_URL"] = "sqlite:///:memory:"

    from opsec_platform.app.main import create_app
    app = create_app()

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    url = f"http://127.0.0.1:{port}"
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("test platform server did not start in time")

    yield url

    server.should_exit = True
    thread.join(timeout=5)


def _get_token(base_url, email="scanner@example.com", password="testpass123"):
    import httpx
    with httpx.Client(base_url=base_url) as client:
        client.post("/auth/register", json={"email": email, "password": password, "org_name": "Test Org"})
        r = client.post("/auth/login", json={"email": email, "password": password})
        set_cookie = r.headers.get("set-cookie", "")
        return set_cookie.split("opsec_session=")[1].split(";")[0]


def test_report_scan_activity_succeeds_with_valid_token(live_platform_url):
    token = _get_token(live_platform_url)
    result = report_scan_activity(live_platform_url, token, _scored_findings(), "my-repo")
    assert "id" in result


def test_reported_activity_actually_appears_in_the_activity_log(live_platform_url):
    import httpx
    token = _get_token(live_platform_url)
    report_scan_activity(live_platform_url, token, _scored_findings(), "my-repo")

    with httpx.Client(base_url=live_platform_url) as client:
        r = client.get("/activity/me", headers={"Authorization": f"Bearer {token}"})
    events = r.json()
    scan_events = [e for e in events if e["event_type"] == "scan_reported"]
    assert len(scan_events) == 1
    assert scan_events[0]["detail"].startswith("my-repo:")


def test_report_scan_activity_with_invalid_token_raises_clear_error(live_platform_url):
    with pytest.raises(ActivityReportError, match="rejected the token"):
        report_scan_activity(live_platform_url, "not-a-real-token", _scored_findings(), "my-repo")


def test_report_scan_activity_rejects_non_local_plain_http():
    with pytest.raises(ActivityReportError, match="plain HTTP"):
        report_scan_activity(
            "http://platform.example.invalid:9999", "some-token", _scored_findings(), "my-repo"
        )

def test_report_scan_activity_rejects_non_http_urls():
    with pytest.raises(ActivityReportError, match="absolute http"):
        report_scan_activity(
            "ftp://platform.example.invalid", "some-token", _scored_findings(), "my-repo"
        )


def test_report_scan_activity_allows_local_http_for_development(live_platform_url):
    token = _get_token(live_platform_url)
    result = report_scan_activity(live_platform_url, token, _scored_findings(), "local-test")
    assert "id" in result


def _create_access_token(base_url, session_token):
    import httpx
    with httpx.Client(base_url=base_url, cookies={"opsec_session": session_token}) as client:
        r = client.post("/auth/tokens", json={"name": "cli test"})
        assert r.status_code == 201, r.text
        return r.json()["token"]


def test_upload_findings_creates_redacted_scan_in_workspace(live_platform_url):
    import httpx
    from opsec_scanner.output.platform_client import upload_findings

    session = _get_token(live_platform_url)
    token = _create_access_token(live_platform_url, session)
    scan = upload_findings(live_platform_url, token, _scored_findings(), "cli-repo", scan_stats={"commits_scanned": 3})
    assert scan["status"] == "completed" and scan["source"] == "cli_upload"
    assert scan["target_label"] == "cli-repo" and scan["total_findings"] == 2

    with httpx.Client(base_url=live_platform_url, headers={"Authorization": f"Bearer {token}"}) as client:
        findings = client.get(f"/scans/{scan['id']}/findings").json()
    assert findings["total"] == 2
    assert "AKIATEST0000000000A" not in str(findings)


def test_upload_payload_never_contains_matched_values():
    from opsec_scanner.output.platform_client import build_upload_payload
    payload = build_upload_payload(_scored_findings(), "x")
    assert "AKIATEST0000000000A" not in str(payload) and "db.internal" not in str(payload)
    assert payload["redacted"] is True


def test_upload_findings_rejects_plain_http():
    from opsec_scanner.output.platform_client import upload_findings
    with pytest.raises(ActivityReportError, match="plain HTTP"):
        upload_findings("http://platform.example.invalid", "t", _scored_findings(), "x")

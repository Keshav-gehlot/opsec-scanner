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

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod-0123456789")
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


# --- --platform-login / create_cli_token ---------------------------------------

def _register(base_url, email="cli-user@example.com", password="testpass123"):
    import httpx
    with httpx.Client(base_url=base_url) as client:
        client.post("/auth/register", json={"email": email, "password": password, "org_name": "CLI Org"})


def test_session_token_from_set_cookie():
    from opsec_scanner.output.platform_client import session_token_from_set_cookie
    assert session_token_from_set_cookie("opsec_session=abc.def; HttpOnly; Path=/") == "abc.def"
    assert session_token_from_set_cookie("other=1") is None


def test_create_cli_token_mints_scoped_access_token_and_signs_session_out(live_platform_url):
    import httpx
    from opsec_scanner.output.platform_client import create_cli_token

    _register(live_platform_url)
    created = create_cli_token(live_platform_url, "cli-user@example.com", "testpass123", "cli test", expires_in_days=30)
    token = created["token"]
    assert token.startswith("opsec_pat_")
    # The access token works for what the CLI needs...
    assert "id" in report_scan_activity(live_platform_url, token, _scored_findings(), "my-repo")
    with httpx.Client(base_url=live_platform_url) as client:
        # ...but not for account management.
        assert client.get("/auth/sessions", headers={"Authorization": f"Bearer {token}"}).status_code == 403
        # The temporary browser session used to mint it was signed out again.
        login = client.post("/auth/login", json={"email": "cli-user@example.com", "password": "testpass123"})
        sessions = client.get("/auth/sessions").json()
    assert login.status_code == 200 and len(sessions) == 1


def test_create_cli_token_wrong_password_gives_clear_error(live_platform_url):
    from opsec_scanner.output.platform_client import create_cli_token

    _register(live_platform_url)
    with pytest.raises(ActivityReportError, match="incorrect"):
        create_cli_token(live_platform_url, "cli-user@example.com", "not-the-password", "cli test")


def test_platform_login_cli_prints_only_an_export_line(live_platform_url):
    import subprocess
    _register(live_platform_url)
    result = subprocess.run(
        [sys.executable, "-m", "opsec_scanner.main", "--platform-login", live_platform_url,
         "--platform-email", "cli-user@example.com", "--token-days", "30"],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "OPSEC_PLATFORM_PASSWORD": "testpass123"},
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1 and lines[0].startswith("export OPSEC_PLATFORM_TOKEN=opsec_pat_")
    assert "testpass123" not in result.stdout + result.stderr


# --- --fail-on-report-error -------------------------------------------------------

def _leak_repo(tmp_path):
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.name", "T"], ["config", "user.email", "t@example.com"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "secret.txt").write_text("postgres://admin:Password123@db.internal.co:5432/main\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo, check=True, capture_output=True)
    return repo


@pytest.mark.parametrize("extra,expected", [([], 0), (["--fail-on-report-error"], 3),
                                            (["--fail-on-report-error", "--fail-on", "LOW"], 1)])
def test_fail_on_report_error_exit_codes(tmp_path, extra, expected):
    import subprocess
    repo = _leak_repo(tmp_path)
    dead = f"http://127.0.0.1:{_free_port()}"  # nothing listens here
    profile = tmp_path / "profile.yaml"
    profile.write_text("name: Test User\naliases: []\nemails: []\ndomains: []\n")
    result = subprocess.run(
        [sys.executable, "-m", "opsec_scanner.main", "--repo", str(repo), "--no-progress", "--profile", str(profile),
         "--output", str(tmp_path / "r.html"), "--report-activity", dead,
         "--report-activity-token", "opsec_pat_dummy", *extra],
        capture_output=True, text=True, timeout=120, cwd=tmp_path,
    )
    assert result.returncode == expected, result.stdout + result.stderr
    assert (tmp_path / "r.html").exists()  # local reports are always written first

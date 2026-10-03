"""
Web workspace: scan import, server-side media/git scans, findings browsing,
diffs, exports, access tokens, CSRF origin checks and page routing.
"""

import io
import json
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")

REPO_ROOT = Path(__file__).resolve().parents[1]
AWS_KEY = "AKIAIOSFODNN7EXAMPLQ"


@pytest.fixture
def client(tmp_path):
    # A file database, not :memory:. In-memory SQLite shares ONE connection
    # across threads (StaticPool), so a request finishing its session would
    # roll back a background scan's transaction mid-flight — a test-only race.
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    os.environ["PLATFORM_DATABASE_URL"] = f"sqlite:///{tmp_path / 'platform.db'}"
    from opsec_platform.app.main import create_app
    return TestClient(create_app())


def signup(client, email="owner@example.com", org="Acme"):
    assert client.post("/auth/register", json={"email": email, "password": "testpass123", "org_name": org}).status_code == 201
    assert client.post("/auth/login", json={"email": email, "password": "testpass123"}).status_code == 200


def export_payload(findings):
    return {"generated_at": "2026-10-01T00:00:00+00:00", "redacted": False, "total_findings": len(findings), "findings": findings}


def finding(rule="aws_access_key", text=AWS_KEY, label="CRITICAL", score=9.5, origin="repo", context="commit abc, file a.py, line 3"):
    return {
        "risk_score": score, "risk_label": label, "rule_id": rule, "category": "credentials",
        "matched_text": text, "matched_text_length": len(text), "base_severity": 9.5,
        "identity_confidence": 1.0, "identity_reason": "generic", "exposure_level": "local_only",
        "source_type": "git_patch", "origin": origin, "context": context, "occurrence_count": 2,
        "metadata": {"name": "Should Not Be Stored"},
    }


def wait(client, scan_id):
    from opsec_platform.app import scan_service
    scan_service.wait_for_idle(120)
    return client.get(f"/scans/{scan_id}").json()


# ---------------------------------------------------------------- pages

def test_dashboard_requires_session_and_login_redirects_when_signed_in(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    assert "authForm" in client.get("/login").text

    signup(client)
    page = client.get("/dashboard", follow_redirects=False)
    assert page.status_code == 200
    assert 'id="authForm"' not in page.text and 'id="appShell"' in page.text
    assert client.get("/login", follow_redirects=False).headers["location"] == "/dashboard"
    assert client.get("/", follow_redirects=False).headers["location"] == "/dashboard"


# ---------------------------------------------------------------- import

def test_import_cli_export_stores_redacted_preview_only(client):
    signup(client)
    payload = export_payload([finding(), finding(rule="internal_ip_range", text="10.20.30.40", label="MEDIUM", score=5.0)])
    r = client.post("/scans/import?label=my-repo", json=payload)
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "completed" and scan["source"] == "json_import"
    assert scan["total_findings"] == 2 and scan["critical_count"] == 1 and scan["medium_count"] == 1
    assert scan["target_label"] == "my-repo"

    body = client.get(f"/scans/{scan['id']}/findings").json()
    assert body["total"] == 2 and body["facets"]["risk"] == {"CRITICAL": 1, "MEDIUM": 1}
    top = body["items"][0]
    assert top["rule_id"] == "aws_access_key" and AWS_KEY not in json.dumps(body)
    assert top["preview"].startswith("AKIA") and "•" in top["preview"]

    from opsec_platform.app import dependencies
    from opsec_platform.app.models import Finding
    db = dependencies._SessionLocal()
    try:
        dumped = json.dumps([{c.name: getattr(f, c.name) for c in Finding.__table__.columns} for f in db.query(Finding).all()], default=str)
    finally:
        db.close()
    assert AWS_KEY not in dumped and "10.20.30.40" not in dumped and "Should Not Be Stored" not in dumped


def test_import_accepts_redacted_export_file_and_demo_file(client):
    signup(client)
    demo = (REPO_ROOT / "demo_findings.json").read_bytes()
    r = client.post("/scans/import", files={"file": ("demo_findings.json", demo, "application/json")})
    assert r.status_code == 201, r.text
    assert r.json()["total_findings"] == json.loads(demo)["total_findings"]
    assert r.json()["target_label"] == "demo_findings"


@pytest.mark.parametrize("payload, code", [
    ({"nope": 1}, 422),
    ({"findings": [{"rule_id": "x"}]}, 422),
    ({"findings": [{"rule_id": "x", "risk_label": "BAD", "risk_score": 1}]}, 422),
])
def test_import_rejects_malformed_exports(client, payload, code):
    signup(client)
    assert client.post("/scans/import", json=payload).status_code == code


def test_import_rejects_invalid_json(client):
    signup(client)
    r = client.post("/scans/import", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_import_requires_authentication(client):
    assert client.post("/scans/import", json=export_payload([finding()])).status_code == 401


# ---------------------------------------------------------------- diff / overview / export

def test_diff_and_overview_track_new_and_resolved(client):
    signup(client)
    first = client.post("/scans/import?label=svc", json=export_payload([finding(), finding(rule="internal_ip_range", text="10.0.0.9", label="LOW", score=2)])).json()
    second = client.post("/scans/import?label=svc", json=export_payload([finding(), finding(rule="github_pat", text="ghp_" + "a" * 36, label="HIGH", score=7)])).json()

    diff = client.get(f"/scans/{second['id']}/diff").json()
    assert diff["previous_scan_id"] == first["id"]
    assert [f["rule_id"] for f in diff["new"]] == ["github_pat"]
    assert [f["rule_id"] for f in diff["resolved"]] == ["internal_ip_range"]
    assert diff["still_open"] == 1

    overview = client.get("/scans/overview").json()
    assert overview["scans_total"] == 2
    target = overview["targets"][0]
    assert target["target_label"] == "svc" and target["scans"] == 2 and target["new"] == 1 and target["resolved"] == 1
    assert overview["open_findings"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert len(overview["trend"]) == 2


def test_exports_are_redacted_and_csv_is_injection_safe(client):
    signup(client)
    scan = client.post("/scans/import", json=export_payload([finding(origin="=cmd|' /C calc'!A0")])).json()
    csv_body = client.get(f"/scans/{scan['id']}/export?format=csv").text
    assert "'=cmd" in csv_body and AWS_KEY not in csv_body
    sarif = client.get(f"/scans/{scan['id']}/export?format=sarif").json()
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["ruleId"] == "aws_access_key"
    js = client.get(f"/scans/{scan['id']}/export?format=json").json()
    assert js["redacted"] is True and AWS_KEY not in json.dumps(js)


def test_findings_filters_and_search(client):
    signup(client)
    scan = client.post("/scans/import", json=export_payload([
        finding(), finding(rule="internal_ip_range", text="10.1.1.1", label="LOW", score=1, origin="infra/hosts.txt"),
    ])).json()
    assert client.get(f"/scans/{scan['id']}/findings?risk=LOW").json()["total"] == 1
    assert client.get(f"/scans/{scan['id']}/findings?q=hosts").json()["items"][0]["rule_id"] == "internal_ip_range"
    assert client.get(f"/scans/{scan['id']}/findings?sort=rule&order=asc").json()["items"][0]["rule_id"] == "aws_access_key"


# ---------------------------------------------------------------- access control

def test_scans_are_private_to_owner_but_visible_to_org_admin(client):
    signup(client, "admin@example.com", "Acme")
    # admin adds a member to the same org
    assert client.post("/auth/register", json={"email": "member@example.com", "password": "testpass123", "org_name": "Acme"}).status_code == 201
    client.post("/auth/logout")
    client.post("/auth/login", json={"email": "member@example.com", "password": "testpass123"})
    member_scan = client.post("/scans/import", json=export_payload([finding()])).json()
    assert client.get("/scans?scope=org").status_code == 403
    client.post("/auth/logout")

    signup(client, "outsider@example.com", "Other")
    assert client.get(f"/scans/{member_scan['id']}").status_code == 404
    assert client.get(f"/scans/{member_scan['id']}/findings").status_code == 404
    assert client.delete(f"/scans/{member_scan['id']}").status_code == 404
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "admin@example.com", "password": "testpass123"})
    assert client.get(f"/scans/{member_scan['id']}").json()["owner_email"] == "member@example.com"
    org_list = client.get("/scans?scope=org").json()
    assert [s["id"] for s in org_list] == [member_scan["id"]]
    assert client.get("/scans").json() == []


def test_delete_scan(client):
    signup(client)
    scan = client.post("/scans/import", json=export_payload([finding()])).json()
    assert client.delete(f"/scans/{scan['id']}").status_code == 204
    assert client.get(f"/scans/{scan['id']}").status_code == 404


# ---------------------------------------------------------------- tokens

def test_access_token_can_upload_but_cannot_manage_account(client):
    signup(client)
    created = client.post("/auth/tokens", json={"name": "laptop cli", "expires_in_days": 30})
    assert created.status_code == 201
    token = created.json()["token"]
    assert token.startswith("opsec_pat_")
    assert client.get("/auth/tokens").json()[0]["prefix"] == token[:16]
    assert "token" not in client.get("/auth/tokens").json()[0]

    bare = TestClient(client.app)
    headers = {"Authorization": f"Bearer {token}"}
    up = bare.post("/scans/import?label=ci", json=export_payload([finding()]), headers=headers)
    assert up.status_code == 201 and up.json()["source"] == "cli_upload"
    assert bare.post("/activity/report-scan", params={"detail": "ci: 1 CRITICAL"}, headers=headers).status_code == 201
    assert bare.get("/auth/me", headers=headers).status_code == 403
    assert bare.post("/auth/tokens", json={"name": "x"}, headers=headers).status_code == 403
    assert bare.get("/auth/sessions", headers=headers).status_code == 403

    token_id = client.get("/auth/tokens").json()[0]["id"]
    assert client.delete(f"/auth/tokens/{token_id}").status_code == 204
    assert bare.get("/scans", headers=headers).status_code == 401


def test_unknown_access_token_rejected(client):
    r = TestClient(client.app).get("/scans", headers={"Authorization": "Bearer opsec_pat_nope"})
    assert r.status_code == 401


# ---------------------------------------------------------------- CSRF

def test_cross_origin_unsafe_requests_are_blocked(client):
    # main's csrf_origin_guard covers the new scan routes too.
    signup(client)
    evil = {"Origin": "https://evil.example"}
    assert client.post("/scans/import", json=export_payload([finding()]), headers=evil).status_code == 403
    assert client.post("/scans/git", json={"url": "https://github.com/a/b"}, headers=evil).status_code == 403
    assert client.delete("/scans/x", headers=evil).status_code == 403
    assert client.post("/scans/import", json=export_payload([finding()]), headers={"Origin": "http://testserver"}).status_code == 201
    # Safe methods are never blocked.
    assert client.get("/scans", headers=evil).status_code == 200


# ---------------------------------------------------------------- identity profile

def test_identity_profile_defaults_and_update(client):
    signup(client)
    profile = client.get("/profile/identity").json()
    assert profile["emails"] == ["owner@example.com"]
    r = client.put("/profile/identity", json={"name": "Owner", "aliases": ["own3r", "own3r"], "emails": ["owner@example.com"],
                                               "domains": ["acme.internal"], "github_handles": [], "home_coordinates": [12.9, 77.6]})
    assert r.status_code == 200 and r.json()["aliases"] == ["own3r"]
    assert client.get("/profile/identity").json()["domains"] == ["acme.internal"]
    assert client.put("/profile/identity", json={"name": "x", "home_coordinates": [200, 0]}).status_code == 422


# ---------------------------------------------------------------- media scans

def _pdf_with_secret() -> bytes:
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), f"aws key {AWS_KEY} and host db01.corp.internal")
    doc.set_metadata({"author": "Owner"})
    data = doc.tobytes()
    doc.close()
    return data


def test_media_scan_finds_secret_in_pdf(client):
    signup(client)
    r = client.post("/scans/media", files=[("files", ("report.pdf", _pdf_with_secret(), "application/pdf"))], data={"label": "pdfs"})
    assert r.status_code == 202, r.text
    scan = wait(client, r.json()["id"])
    assert scan["status"] == "completed", scan
    findings = client.get(f"/scans/{scan['id']}/findings").json()["items"]
    rules = {f["rule_id"] for f in findings}
    assert "aws_access_key" in rules
    assert all(f["origin"].endswith("report.pdf") and "/tmp" not in f["origin"] for f in findings)
    assert AWS_KEY not in json.dumps(findings)


def test_media_scan_rejects_unsupported_type_and_oversize(client, monkeypatch):
    signup(client)
    r = client.post("/scans/media", files=[("files", ("evil.exe", b"MZ", "application/octet-stream"))])
    assert r.status_code == 415
    monkeypatch.setenv("PLATFORM_SCAN_MEDIA_MAX_FILE_MB", "1")
    big = b"0" * (1024 * 1024 + 10)
    r = client.post("/scans/media", files=[("files", ("big.pdf", big, "application/pdf"))])
    assert r.status_code == 413


def test_server_side_scans_can_be_disabled(client, monkeypatch):
    signup(client)
    monkeypatch.setenv("PLATFORM_WEB_SCANS_ENABLED", "false")
    r = client.post("/scans/git", json={"url": "https://github.com/owner/repo"})
    assert r.status_code == 403
    assert client.get("/scans/capabilities").json()["web_scans_enabled"] is False


# ---------------------------------------------------------------- git scans

@pytest.mark.parametrize("url", [
    "http://github.com/a/b",
    "https://evil.example/a/b",
    "https://user:pw@github.com/a/b",
    "https://github.com:8443/a/b",
    "https://github.com/a/b?x=1",
    "https://github.com/a",
    "https://github.com/a/../../etc",
    "file:///etc/passwd",
    "ssh://git@github.com/a/b",
    "--upload-pack=touch /tmp/pwned",
    "https://169.254.169.254/latest/meta",
])
def test_git_url_validation_rejects_unsafe_urls(url):
    from opsec_platform.app.scan_service import ScanInputError, normalize_git_url
    with pytest.raises(ScanInputError):
        normalize_git_url(url)


def test_git_url_validation_accepts_public_repo_urls():
    from opsec_platform.app.scan_service import normalize_git_url
    assert normalize_git_url("https://github.com/Keshav-gehlot/opsec-scanner.git") == "https://github.com/Keshav-gehlot/opsec-scanner.git"
    assert normalize_git_url("https://gitlab.com/group/sub/project/") == "https://gitlab.com/group/sub/project"


def _make_repo(path: Path) -> None:
    path.mkdir(parents=True)
    env = {**os.environ, "GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@acme.internal",
           "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": "dev@acme.internal"}
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    (path / "config.py").write_text(f'AWS = "{AWS_KEY}"\n')
    subprocess.run(["git", "-C", str(path), "add", "."], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True, env=env)


def test_git_scan_runs_engine_on_cloned_repo(client, monkeypatch, tmp_path):
    from opsec_platform.app import scan_service

    source = tmp_path / "src"
    _make_repo(source)
    calls = {}

    def fake_clone(url, dest, depth):
        calls.update(url=url, depth=depth)
        subprocess.run(["git", "clone", "-q", str(source), str(dest)], check=True)

    monkeypatch.setattr(scan_service, "clone_repository", fake_clone)
    signup(client)
    r = client.post("/scans/git", json={"url": "https://github.com/acme/app", "depth": 5000})
    assert r.status_code == 202, r.text
    scan = wait(client, r.json()["id"])
    assert scan["status"] == "completed", scan
    assert calls == {"url": "https://github.com/acme/app", "depth": 1000}
    assert scan["target_label"] == "github.com/acme/app"
    findings = client.get(f"/scans/{scan['id']}/findings").json()["items"]
    assert any(f["rule_id"] == "aws_access_key" for f in findings)
    assert all(f["origin"].startswith("https://github.com/acme/app") for f in findings)
    assert all(f["exposure_level"] == "public_reachable" for f in findings)


def test_git_scan_failure_is_reported(client, monkeypatch):
    from opsec_platform.app import scan_service

    def fake_clone(url, dest, depth):
        raise scan_service.ScanInputError("Repository not found or not public.")

    monkeypatch.setattr(scan_service, "clone_repository", fake_clone)
    signup(client)
    scan = wait(client, client.post("/scans/git", json={"url": "https://github.com/acme/missing"}).json()["id"])
    assert scan["status"] == "failed" and scan["error"] == "Repository not found or not public."


def test_stale_scans_are_marked_failed(tmp_path):
    from datetime import datetime, timedelta, timezone
    from opsec_platform.app import dependencies, scan_service
    from opsec_platform.app.database import make_engine
    from opsec_platform.app.models import Scan, User

    dependencies.configure_db(make_engine(f"sqlite:///{tmp_path / 'stale.db'}"))
    from opsec_platform.app.database import init_db
    init_db(dependencies._engine)
    db = dependencies._SessionLocal()
    try:
        user = User(email="stale@example.com", auth_provider="local")
        db.add(user)
        db.flush()
        old = Scan(user_id=user.id, source="git_url", target_label="x", status="running",
                   created_at=datetime.now(timezone.utc) - timedelta(hours=2))
        fresh = Scan(user_id=user.id, source="git_url", target_label="y", status="running")
        db.add_all([old, fresh])
        db.commit()
        assert scan_service.recover_stale_scans(db) == 1
        db.refresh(old)
        db.refresh(fresh)
        assert old.status == "failed" and fresh.status == "running"
    finally:
        db.close()


def test_health_reports_scanner_rules(client):
    health = client.get("/health").json()
    assert health["scanner"]["ok"] is True and health["scanner"]["rules_loaded"] >= 20


def test_redact_preview_never_returns_full_value():
    from opsec_platform.app.scan_service import redact_preview
    for value in ["a", "abcdefg", "abcdefgh", AWS_KEY, "x" * 200]:
        preview = redact_preview(value)
        assert preview != value and "•" in preview

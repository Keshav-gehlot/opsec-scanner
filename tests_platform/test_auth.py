"""
Auth platform test suite. Each test gets a fresh in-memory SQLite DB and
a fresh FastAPI app instance so tests can't leak state into each other.
"""

import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")  # TestClient/local dev use plain http


@pytest.fixture
def client():
    # Fresh app + fresh in-memory DB per test.
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    os.environ["PLATFORM_DATABASE_URL"] = "sqlite:///:memory:"

    from opsec_platform.app.main import create_app
    app = create_app()
    return TestClient(app)


def _register(client, email="test@example.com", password="testpass123", org="Test Org"):
    return client.post("/auth/register", json={"email": email, "password": password, "org_name": org})


def test_register_creates_user(client):
    r = _register(client)
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "test@example.com"
    assert body["auth_provider"] == "local"


def test_register_duplicate_email_rejected(client):
    _register(client)
    r = _register(client)
    assert r.status_code == 409


def test_register_short_password_rejected(client):
    r = client.post("/auth/register", json={"email": "x@example.com", "password": "short", "org_name": "Org"})
    assert r.status_code == 422  # pydantic min_length validation


def test_login_with_correct_password_succeeds(client):
    _register(client)
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 200
    assert "opsec_session" in r.cookies


def test_login_with_wrong_password_rejected(client):
    _register(client)
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    assert r.status_code == 401


def test_login_nonexistent_user_rejected_with_same_error_as_wrong_password(client):
    # Same status + message as a wrong password — an attacker probing
    # this endpoint shouldn't be able to tell which emails have accounts.
    r1 = client.post("/auth/login", json={"email": "nobody@example.com", "password": "whatever123"})
    _register(client)
    r2 = client.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    assert r1.status_code == r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"]


def test_me_requires_authentication(client):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_me_returns_current_user_when_authenticated(client):
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    r = client.get("/auth/me")
    assert r.status_code == 200
    assert r.json()["email"] == "test@example.com"


def test_me_rejects_tampered_cookie(client):
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    client.cookies["opsec_session"] = client.cookies["opsec_session"][:-4] + "xxxx"
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_logout_revokes_session_not_just_clears_cookie(client):
    # The important property: logout must invalidate the session
    # server-side, not just tell the browser to forget the cookie — a
    # copied/leaked token must stop working after logout.
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    token = client.cookies["opsec_session"]

    r = client.post("/auth/logout")
    assert r.status_code == 200

    # Re-attach the same (now-revoked) token manually, simulating an
    # attacker who captured it before logout, and confirm it's dead.
    client.cookies["opsec_session"] = token
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_login_failure_is_logged_to_activity(client):
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    r = client.get("/activity/me")
    assert r.status_code == 200
    events = [e["event_type"] for e in r.json()]
    assert "login_failed" in events
    assert "login_success" in events


def test_registration_is_logged_to_activity(client):
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    r = client.get("/activity/me")
    events = [e["event_type"] for e in r.json()]
    assert "user_created" in events


def test_report_scan_activity_endpoint(client):
    _register(client)
    client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    r = client.post("/activity/report-scan", params={"detail": "3 CRITICAL findings in my-repo"})
    assert r.status_code == 201

    r = client.get("/activity/me")
    events = {e["event_type"]: e["detail"] for e in r.json()}
    assert events.get("scan_reported") == "3 CRITICAL findings in my-repo"


def test_health_endpoint_reports_no_sso_configured_by_default(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["sso_providers_configured"] == []


def test_oauth_login_returns_clear_error_when_provider_not_configured(client):
    for provider in ("google", "github", "microsoft", "apple"):
        r = client.get(f"/auth/oauth/{provider}/login", follow_redirects=False)
        assert r.status_code == 501, f"{provider} should be 'not configured' (501), got {r.status_code}"
        assert provider.capitalize() in r.json()["detail"]
        assert "CLIENT_ID" in r.json()["detail"]


def test_oauth_callback_route_is_registered_when_provider_not_configured(client):
    # Regression test: APIRouter.route registered this Starlette-style route
    # incorrectly for FastAPI and production returned 404 for the callback.
    # The callback must exist even before credentials are configured; the
    # provider configuration gate should then return the expected 501.
    for method in ("get", "post"):
        r = getattr(client, method)("/auth/oauth/google/callback", follow_redirects=False)
        assert r.status_code == 501
        assert "Google" in r.json()["detail"]


def test_oauth_login_rejects_unknown_provider(client):
    r = client.get("/auth/oauth/facebook/login", follow_redirects=False)
    assert r.status_code == 404


def test_oauth_login_configured_provider_without_discovery_redirects_correctly(monkeypatch):
    # GitHub doesn't require a live OIDC-discovery network call (static
    # URLs, unlike google/microsoft/apple), so this verifies the Authlib
    # wiring itself — redirect URL, client_id, callback URI, scopes,
    # CSRF state param — without depending on outbound network access
    # working in whatever environment the test suite runs in.
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-github-client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-github-client-secret")
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://myplatform.example.com")

    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    app = create_app()
    c = TestClient(app)

    r = c.get("/auth/oauth/github/login", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers["location"]
    assert location.startswith("https://github.com/login/oauth/authorize")
    assert "client_id=test-github-client-id" in location
    assert "myplatform.example.com%2Fauth%2Foauth%2Fgithub%2Fcallback" in location
    assert "state=" in location  # CSRF protection param must be present


def test_oauth_login_returns_clean_error_not_raw_exception_when_provider_unreachable(monkeypatch):
    # Regression test: an OIDC provider's discovery-document fetch
    # failing (network hiccup, provider outage, or — as found while
    # testing this — a sandboxed environment with restricted egress)
    # previously surfaced as an unhandled httpx.HTTPStatusError
    # traceback to whoever clicked "sign in with Google," instead of a
    # clean error response.
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")

    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    app = create_app()
    c = TestClient(app)

    r = c.get("/auth/oauth/google/login", follow_redirects=False)
    # Whether this environment's network can actually reach Google or
    # not, the response must never be a raw 500/unhandled exception —
    # only a clean redirect (network worked) or a clean 502 (it didn't).
    assert r.status_code in (302, 502)
    if r.status_code == 502:
        assert "Google" in r.json()["detail"]


def test_inactive_account_cannot_log_in(client):
    _register(client)
    # Deactivate directly via the DB layer (no admin-deactivation route
    # exists yet — this simulates that state to test the login-side check).
    import opsec_platform.app.dependencies as deps
    db = deps._SessionLocal()
    from opsec_platform.app.models import User
    user = db.query(User).filter(User.email == "test@example.com").first()
    user.is_active = False
    db.commit()
    db.close()

    r = client.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 403


def test_bootstrapping_a_new_org_requires_no_authentication(client):
    r = _register(client, email="founder@example.com", org="Brand New Org")
    assert r.status_code == 201
    assert r.json()["is_org_admin"] is True


def test_first_user_of_a_new_org_becomes_org_admin(client):
    r = _register(client, email="founder@example.com", org="Some Org")
    assert r.json()["is_org_admin"] is True


def test_unauthenticated_caller_cannot_add_user_to_existing_org(client):
    # Regression test for the gap explicitly flagged in the previous
    # pass's README ("/auth/register has no admin gate yet") — an
    # unauthenticated request must not be able to add accounts to an
    # org that already has members.
    _register(client, email="founder@example.com", org="Acme")
    r = _register(client, email="intruder@example.com", org="Acme")
    assert r.status_code == 401


def test_non_admin_member_cannot_add_users(client):
    _register(client, email="founder@example.com", org="Acme")
    client.post("/auth/login", json={"email": "founder@example.com", "password": "testpass123"})
    _register(client, email="member@example.com", org="Acme")  # admin adds a regular member

    # Log in as the non-admin member and try to add someone else.
    member_client_cookies = client.cookies
    client.cookies.clear()
    client.post("/auth/login", json={"email": "member@example.com", "password": "testpass123"})
    r = _register(client, email="another@example.com", org="Acme")
    assert r.status_code == 403


def test_admin_can_add_users_to_their_own_org(client):
    _register(client, email="founder@example.com", org="Acme")
    client.post("/auth/login", json={"email": "founder@example.com", "password": "testpass123"})
    r = _register(client, email="member@example.com", org="Acme")
    assert r.status_code == 201
    assert r.json()["is_org_admin"] is False  # new members are non-admin by default


def test_admin_of_one_org_cannot_add_users_to_a_different_org(client):
    # An admin's authority is scoped to their own org — being an admin
    # somewhere doesn't grant authority everywhere.
    _register(client, email="acme-admin@example.com", org="Acme")
    _register(client, email="widgetco-admin@example.com", org="WidgetCo")

    client.post("/auth/login", json={"email": "acme-admin@example.com", "password": "testpass123"})
    r = _register(client, email="intruder@example.com", org="WidgetCo")
    assert r.status_code == 403


def test_login_rate_limit_blocks_after_threshold_failures(monkeypatch):
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    _register(c)
    for _ in range(3):
        r = c.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
        assert r.status_code == 401

    # Regression-critical: even the CORRECT password must be blocked
    # once the threshold is hit — otherwise rate limiting only protects
    # against a mistyped password, not an actual brute-force attempt.
    r = c.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 429


def test_login_rate_limit_does_not_block_a_fresh_account_with_no_prior_failures(monkeypatch):
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    _register(c)
    r = c.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 200


def test_login_rate_limit_applies_to_nonexistent_accounts_too(monkeypatch):
    # Rate limiting must also cover probing emails that were never
    # registered — otherwise it's trivially bypassed by fishing for
    # valid accounts before ever hitting a real one.
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    for _ in range(3):
        r = c.post("/auth/login", json={"email": "nobody@example.com", "password": "guess"})
        assert r.status_code == 401

    r = c.post("/auth/login", json={"email": "nobody@example.com", "password": "another-guess"})
    assert r.status_code == 429


def test_login_rate_limit_resets_after_window_expires(monkeypatch):
    from datetime import datetime, timedelta, timezone

    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    _register(c)
    for _ in range(3):
        c.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})

    r = c.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 429

    from opsec_platform.app.models import ActivityLog
    db = deps._SessionLocal()
    old_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    db.query(ActivityLog).filter(ActivityLog.event_type == "login_failed").update({"timestamp": old_time})
    db.commit()
    db.close()

    r = c.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})
    assert r.status_code == 200


def test_rate_limited_attempt_is_logged_with_its_own_event_type(monkeypatch):
    # Must not log as LOGIN_FAILED, or a rate-limited request would
    # itself extend the window it's being rate-limited under.
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "2")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    _register(c)
    c.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    c.post("/auth/login", json={"email": "test@example.com", "password": "wrongpassword"})
    c.post("/auth/login", json={"email": "test@example.com", "password": "testpass123"})

    db = deps._SessionLocal()
    from opsec_platform.app.models import ActivityLog
    event_types = [row.event_type for row in db.query(ActivityLog).all()]
    db.close()
    assert event_types.count("login_failed") == 2
    assert event_types.count("login_rate_limited") == 1


def test_login_ip_rate_limit_blocks_after_threshold_failures_from_same_ip(monkeypatch):
    monkeypatch.setenv("PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS", "3")
    monkeypatch.setenv("PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS", "3")
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app
    c = TestClient(create_app())

    _register(c, email="alice@example.com")
    _register(c, email="bob@example.com")

    for _ in range(3):
        r = c.post("/auth/login", json={"email": "alice@example.com", "password": "wrongpassword"})
        assert r.status_code == 401

    r = c.post("/auth/login", json={"email": "bob@example.com", "password": "testpass123"})
    assert r.status_code == 429

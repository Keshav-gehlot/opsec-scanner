"""
Deployment-safety tests for the OAuth handshake:

- the OAuth state cookie has its own secret (never the JWT secret or an
  OAuth client secret) and HTTPS deployments must supply it;
- callback URLs come from PLATFORM_BASE_URL, never from request headers;
- failed callbacks release their DB session and don't log raw errors;
- /health reports the deployed commit.
"""

import pytest
from fastapi.testclient import TestClient

GOOD_OAUTH_SECRET = "oauth-state-secret-for-tests-0123456789abcdef"
GOOD_JWT_SECRET = "jwt-secret-for-tests-0123456789abcdefghijklmn"


def _base_env(monkeypatch, *, secure: bool):
    monkeypatch.setenv("PLATFORM_JWT_SECRET", GOOD_JWT_SECRET)
    monkeypatch.setenv("PLATFORM_COOKIE_SECURE", "true" if secure else "false")
    monkeypatch.setenv("PLATFORM_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret-value")
    for name in ("PLATFORM_BASE_URL", "PLATFORM_OAUTH_SESSION_SECRET", "RENDER_GIT_COMMIT",
                 "VERCEL_GIT_COMMIT_SHA", "PLATFORM_GIT_COMMIT"):
        monkeypatch.delenv(name, raising=False)


def _app(monkeypatch, captured=None):
    import opsec_platform.app.dependencies as deps
    from opsec_platform.app import oauth_routes

    deps._engine = None
    deps._SessionLocal = None

    class FakeClient:
        async def authorize_redirect(self, request, redirect_uri):
            from fastapi.responses import RedirectResponse
            assert request.session is not None
            if captured is not None:
                captured["redirect_uri"] = redirect_uri
            return RedirectResponse("https://accounts.google.com/o/oauth2/auth", status_code=302)

    class FakeOAuth:
        def create_client(self, provider):
            return FakeClient()

    monkeypatch.setattr(oauth_routes, "build_oauth_registry", lambda settings: FakeOAuth())

    from opsec_platform.app.main import create_app

    return TestClient(create_app())


def test_https_deployment_without_oauth_session_secret_disables_sso(monkeypatch):
    _base_env(monkeypatch, secure=True)
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://app.example.com")
    client = _app(monkeypatch)

    response = client.get("/auth/oauth/google/login", follow_redirects=False)
    assert response.status_code == 503
    # Don't leak which variable is missing to anonymous callers.
    assert "PLATFORM_" not in response.text
    assert client.get("/health").json()["sso_providers_configured"] == []


def test_https_deployment_without_base_url_disables_sso(monkeypatch):
    _base_env(monkeypatch, secure=True)
    monkeypatch.setenv("PLATFORM_OAUTH_SESSION_SECRET", GOOD_OAUTH_SECRET)
    client = _app(monkeypatch)

    assert client.get("/auth/oauth/google/login", follow_redirects=False).status_code == 503


@pytest.mark.parametrize("reused", [GOOD_JWT_SECRET, "test-client-secret-value-padded-to-32-bytes!!"])
def test_oauth_session_secret_must_not_reuse_other_secrets(monkeypatch, reused):
    _base_env(monkeypatch, secure=True)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret-value-padded-to-32-bytes!!")
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://app.example.com")
    monkeypatch.setenv("PLATFORM_OAUTH_SESSION_SECRET", reused)
    from opsec_platform.app.config import get_settings

    problems = get_settings().oauth_config_problems()
    assert any("must not reuse" in p for p in problems)


def test_https_deployment_uses_base_url_and_ignores_forwarded_host(monkeypatch):
    _base_env(monkeypatch, secure=True)
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://app.example.com/")
    monkeypatch.setenv("PLATFORM_OAUTH_SESSION_SECRET", GOOD_OAUTH_SECRET)
    captured = {}
    client = _app(monkeypatch, captured)

    response = client.get(
        "/auth/oauth/google/login",
        headers={"X-Forwarded-Host": "evil.example.net", "X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert captured["redirect_uri"] == "https://app.example.com/auth/oauth/google/callback"
    assert client.get("/health").json()["sso_providers_configured"] == ["google"]


def test_local_dev_ignores_forwarded_host(monkeypatch):
    _base_env(monkeypatch, secure=False)
    captured = {}
    client = _app(monkeypatch, captured)

    response = client.get(
        "/auth/oauth/google/login",
        headers={"X-Forwarded-Host": "evil.example.net", "X-Forwarded-Proto": "https"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert captured["redirect_uri"] == "http://testserver/auth/oauth/google/callback"


def _track_db_sessions(monkeypatch):
    import opsec_platform.app.dependencies as deps

    real_factory = deps._SessionLocal
    opened = []

    def tracking_factory():
        session = real_factory()
        state = {"closed": False}
        real_close = session.close

        def close():
            state["closed"] = True
            real_close()

        session.close = close
        opened.append(state)
        return session

    monkeypatch.setattr(deps, "_SessionLocal", tracking_factory)
    return opened


@pytest.mark.parametrize("identity", [
    {"provider_user_id": None, "email": "p@example.com", "email_verified": True},
    {"provider_user_id": "g-1", "email": None, "email_verified": True},
    {"provider_user_id": "g-1", "email": "p@example.com", "email_verified": False},
])
def test_rejected_callback_closes_db_session(monkeypatch, identity):
    _base_env(monkeypatch, secure=False)
    client = _app(monkeypatch)
    opened = _track_db_sessions(monkeypatch)
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return dict(identity, display_name="P")

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)
    response = client.get("/auth/oauth/google/callback?code=c&state=s", follow_redirects=False)

    assert response.status_code == 400
    assert opened and all(s["closed"] for s in opened)


def test_failed_token_exchange_does_not_log_raw_error(monkeypatch):
    _base_env(monkeypatch, secure=False)
    client = _app(monkeypatch)
    opened = _track_db_sessions(monkeypatch)
    from opsec_platform.app import oauth_routes

    logged = []
    monkeypatch.setattr(oauth_routes, "log_activity", lambda db, event, **kw: logged.append(kw.get("detail", "")))

    async def failing_identity(provider, oauth, request):
        raise RuntimeError("provider said: access_token=SENSITIVE-VALUE")

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", failing_identity)
    response = client.get("/auth/oauth/google/callback?code=c&state=s", follow_redirects=False)

    assert response.status_code == 401
    assert logged and all("SENSITIVE-VALUE" not in d for d in logged)
    assert "RuntimeError" in logged[0]
    assert opened and all(s["closed"] for s in opened)


def test_health_reports_deployed_commit(monkeypatch):
    _base_env(monkeypatch, secure=False)
    monkeypatch.setenv("RENDER_GIT_COMMIT", "d297ed669bee6f7034860912de41d37f43b5cbfb")
    client = _app(monkeypatch)

    assert client.get("/health").json()["commit"] == "d297ed669bee"
    assert client.get("/health/live").json()["commit"] == "d297ed669bee"

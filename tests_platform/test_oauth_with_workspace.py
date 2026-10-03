"""
The web workspace must leave the working OAuth flow untouched: OAuth
routes are not modified, provider callbacks bypass the new Origin check
(Apple posts its callback cross-site), and a successful SSO sign-in lands
directly in the workspace.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def oauth_client(monkeypatch):
    monkeypatch.setenv("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
    monkeypatch.setenv("PLATFORM_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.delenv("PLATFORM_BASE_URL", raising=False)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")

    import opsec_platform.app.dependencies as deps

    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app

    return TestClient(create_app())


def test_google_sign_in_lands_in_workspace_without_login_page(oauth_client, monkeypatch):
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return {"provider_user_id": "g-1", "email": "sso@example.com", "email_verified": True, "display_name": "SSO"}

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)
    callback = oauth_client.get("/auth/oauth/google/callback?code=c&state=s", follow_redirects=False)
    assert callback.status_code == 302 and callback.headers["location"] == "/dashboard"

    page = oauth_client.get("/dashboard", follow_redirects=False)
    assert page.status_code == 200
    assert 'id="appShell"' in page.text and 'id="authForm"' not in page.text

    # SSO users can use the scanner like anyone else.
    assert oauth_client.get("/scans").status_code == 200
    assert oauth_client.get("/profile/identity").json()["emails"] == ["sso@example.com"]


def test_oauth_callbacks_are_exempt_from_origin_check(oauth_client):
    # A cross-site POST to a provider callback (Apple uses form_post) must
    # reach the OAuth route rather than the CSRF guard.
    response = oauth_client.post(
        "/auth/oauth/apple/callback", data={"code": "x", "state": "y"},
        headers={"Origin": "https://appleid.apple.com"}, follow_redirects=False,
    )
    assert "Cross-origin request blocked" not in response.text


def test_sso_link_required_notice_still_reaches_login_page(oauth_client):
    response = oauth_client.get("/?sso=link_required", follow_redirects=False)
    assert response.status_code == 200 and 'id="authForm"' in response.text

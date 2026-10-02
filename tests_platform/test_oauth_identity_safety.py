"""
OAuth identity safety tests for every supported provider.

The callback links identities by email, so an unverified provider email
must never be accepted for account creation or linking.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def oauth_client(monkeypatch):
    monkeypatch.setenv("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
    monkeypatch.setenv("PLATFORM_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://opsec-scanner-seven.vercel.app")
    for provider in ("GOOGLE", "GITHUB", "MICROSOFT", "APPLE"):
        monkeypatch.setenv(f"{provider}_CLIENT_ID", "test-client-id")
        monkeypatch.setenv(f"{provider}_CLIENT_SECRET", "test-client-secret")

    import opsec_platform.app.dependencies as deps

    deps._engine = None
    deps._SessionLocal = None

    from opsec_platform.app.main import create_app

    return TestClient(create_app())


@pytest.mark.parametrize("provider", ["google", "github", "microsoft", "apple"])
def test_unverified_oauth_email_is_rejected_for_all_providers(oauth_client, monkeypatch, provider):
    from opsec_platform.app import oauth_routes

    async def fake_identity(current_provider, oauth, request):
        assert current_provider == provider
        return {
            "provider_user_id": f"{provider}-unverified-user",
            "email": "person@example.com",
            "email_verified": False,
            "display_name": "Example Person",
        }

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)

    response = oauth_client.get(
        f"/auth/oauth/{provider}/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "verified email" in response.json()["detail"].lower()
    assert oauth_client.get("/auth/me").status_code == 401


def test_verified_github_identity_can_create_session(oauth_client, monkeypatch):
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return {
            "provider_user_id": "github-user-123",
            "email": "person@example.com",
            "email_verified": True,
            "display_name": "Example Person",
        }

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)

    response = oauth_client.get(
        "/auth/oauth/github/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert oauth_client.get("/auth/me").json()["auth_provider"] == "github"

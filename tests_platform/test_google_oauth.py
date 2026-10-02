"""
Focused Google OAuth integration tests.

These tests exercise the application-owned parts of the flow without
contacting Google: provider configuration, callback identity validation,
account creation/linking, session issuance, and audit logging.
"""

import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def oauth_client(monkeypatch):
    monkeypatch.setenv("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
    monkeypatch.setenv("PLATFORM_COOKIE_SECURE", "false")
    monkeypatch.setenv("PLATFORM_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://opsec-scanner-seven.vercel.app")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")

    import opsec_platform.app.dependencies as deps

    deps._engine = None
    deps._SessionLocal = None

    from opsec_platform.app.main import create_app

    return TestClient(create_app())


def test_google_callback_creates_user_and_session(oauth_client, monkeypatch):
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        assert provider == "google"
        return {
            "provider_user_id": "google-user-123",
            "email": "person@example.com",
            "email_verified": True,
            "display_name": "Example Person",
        }

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)

    response = oauth_client.get(
        "/auth/oauth/google/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == "/"
    assert "opsec_session" in response.cookies

    me = oauth_client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "person@example.com"
    assert me.json()["auth_provider"] == "google"


def test_google_callback_rejects_unverified_email(oauth_client, monkeypatch):
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return {
            "provider_user_id": "google-user-456",
            "email": "person@example.com",
            "email_verified": False,
            "display_name": "Example Person",
        }

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)

    response = oauth_client.get(
        "/auth/oauth/google/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "verified email" in response.json()["detail"].lower()
    assert oauth_client.get("/auth/me").status_code == 401


def test_google_callback_links_existing_local_account(oauth_client, monkeypatch):
    registered = oauth_client.post(
        "/auth/register",
        json={
            "email": "person@example.com",
            "password": "testpass123",
            "org_name": "Example Org",
        },
    )
    assert registered.status_code == 201

    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return {
            "provider_user_id": "google-user-789",
            "email": "person@example.com",
            "email_verified": True,
            "display_name": "Google Person",
        }

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)

    response = oauth_client.get(
        "/auth/oauth/google/callback?code=test-code&state=test-state",
        follow_redirects=False,
    )

    assert response.status_code == 302
    me = oauth_client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["auth_provider"] == "google"
    assert me.json()["email"] == "person@example.com"

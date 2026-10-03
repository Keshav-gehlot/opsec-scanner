"""
Account-linking safety and the repair of accounts that legacy SSO linking
had converted to SSO-only (which silently disabled their password).
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PLATFORM_JWT_SECRET", "jwt-secret-for-tests-0123456789abcdefghijklmn")
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


def _google_identity(monkeypatch, sub, email):
    from opsec_platform.app import oauth_routes

    async def fake_identity(provider, oauth, request):
        return {"provider_user_id": sub, "email": email, "email_verified": True, "display_name": "G"}

    monkeypatch.setattr(oauth_routes, "_fetch_provider_identity", fake_identity)


def _callback(client):
    return client.get("/auth/oauth/google/callback?code=c&state=s", follow_redirects=False)


def _register(client, email, password="testpass123", org="Org " + "x"):
    r = client.post("/auth/register", json={"email": email, "password": password, "org_name": org + email})
    assert r.status_code == 201
    return r.json()


def test_legacy_converted_account_gets_password_login_back(client):
    """Reproduces the production lockout: a password account whose
    auth_provider was overwritten to 'google' by legacy email linking."""
    _register(client, "owner@example.com")

    import opsec_platform.app.dependencies as deps
    from opsec_platform.app.database import backfill_user_identities
    from opsec_platform.app.models import User, UserIdentity

    db = deps._SessionLocal()
    user = db.query(User).filter(User.email == "owner@example.com").one()
    user.auth_provider = "google"
    user.provider_user_id = "google-sub-legacy"
    db.commit()
    db.close()

    # Password login no longer gates on auth_provider, so it works even
    # before the startup repair runs.
    client.cookies.clear()
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": "testpass123"}).status_code == 200

    backfill_user_identities(deps._engine)
    backfill_user_identities(deps._engine)  # idempotent

    db = deps._SessionLocal()
    user = db.query(User).filter(User.email == "owner@example.com").one()
    identities = db.query(UserIdentity).filter(UserIdentity.user_id == user.id).all()
    assert user.auth_provider == "local"
    assert user.provider_user_id is None
    assert [(i.provider, i.provider_user_id) for i in identities] == [("google", "google-sub-legacy")]
    db.close()

    client.cookies.clear()
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": "testpass123"}).status_code == 200


def test_legacy_converted_account_still_signs_in_with_google(client, monkeypatch):
    _register(client, "owner@example.com")
    import opsec_platform.app.dependencies as deps
    from opsec_platform.app.database import backfill_user_identities
    from opsec_platform.app.models import User

    db = deps._SessionLocal()
    user = db.query(User).filter(User.email == "owner@example.com").one()
    user.auth_provider, user.provider_user_id = "google", "google-sub-legacy"
    db.commit()
    db.close()
    backfill_user_identities(deps._engine)

    client.cookies.clear()
    _google_identity(monkeypatch, "google-sub-legacy", "owner@example.com")
    response = _callback(client)
    assert response.status_code == 302
    assert response.headers["location"] == "/dashboard"
    assert client.get("/auth/me").json()["email"] == "owner@example.com"


def test_pending_link_is_not_applied_to_a_different_account(client, monkeypatch):
    _register(client, "victim@example.com")
    _register(client, "other@example.com")
    client.cookies.clear()

    _google_identity(monkeypatch, "google-sub-v", "victim@example.com")
    assert _callback(client).headers["location"] == "/?sso=link_required"

    # Signing in as a different account must not attach victim's Google identity.
    assert client.post("/auth/login", json={"email": "other@example.com", "password": "testpass123"}).status_code == 200
    client.post("/auth/logout")
    client.cookies.clear()

    assert _callback(client).headers["location"] == "/?sso=link_required"


def test_new_google_user_email_is_normalized(client, monkeypatch):
    _register(client, "mixed@example.com")
    client.cookies.clear()
    _google_identity(monkeypatch, "google-sub-m", "Mixed@Example.com")
    # Case differences must not create a duplicate account or bypass linking.
    assert _callback(client).headers["location"] == "/?sso=link_required"

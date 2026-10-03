import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("PLATFORM_JWT_SECRET", "ci-test-secret-012345678901234567890123456789")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")


@pytest.fixture
def client():
    import opsec_platform.app.dependencies as deps
    deps._engine = None
    deps._SessionLocal = None
    os.environ["PLATFORM_DATABASE_URL"] = "sqlite:///:memory:"
    from opsec_platform.app.main import create_app
    return TestClient(create_app())



def register(client: TestClient, email: str, org: str = "Acme"):
    return client.post("/auth/register", json={
        "email": email,
        "password": "testpass123",
        "org_name": org,
    })


def login(client: TestClient, email: str):
    return client.post("/auth/login", json={"email": email, "password": "testpass123"})


def test_session_listing_marks_current_session(client):
    assert register(client, "owner@example.com").status_code == 201
    assert login(client, "owner@example.com").status_code == 200

    response = client.get("/auth/sessions")
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 1
    assert sessions[0]["current"] is True
    assert sessions[0]["revoked"] is False


def test_cannot_revoke_current_session_via_session_endpoint(client):
    register(client, "owner@example.com")
    login(client, "owner@example.com")
    session_id = client.get("/auth/sessions").json()[0]["id"]

    response = client.delete(f"/auth/sessions/{session_id}")
    assert response.status_code == 400

    assert client.get("/auth/me").status_code == 200


def test_revoke_other_session(client):
    register(client, "owner@example.com")
    login(client, "owner@example.com")

    first_token = client.cookies["opsec_session"]
    client.cookies.clear()
    login(client, "owner@example.com")
    sessions = client.get("/auth/sessions").json()
    assert len(sessions) == 2

    other = next(row for row in sessions if not row["current"])
    response = client.delete(f"/auth/sessions/{other['id']}")
    assert response.status_code == 204

    # The current session remains usable.
    assert client.get("/auth/me").status_code == 200

    # The revoked token cannot be used anymore.
    client.cookies["opsec_session"] = first_token
    assert client.get("/auth/me").status_code == 401


def test_revoke_other_sessions_keeps_current_session(client):
    register(client, "owner@example.com")
    login(client, "owner@example.com")
    client.cookies.clear()
    login(client, "owner@example.com")

    response = client.post("/auth/sessions/revoke-others")
    assert response.status_code == 200
    assert response.json()["revoked"] == 1
    assert len(client.get("/auth/sessions").json()) == 1
    assert client.get("/auth/me").status_code == 200


def test_org_admin_can_list_and_deactivate_member(client):
    register(client, "owner@example.com")
    login(client, "owner@example.com")
    assert register(client, "member@example.com").status_code == 201

    members = client.get("/auth/org/members")
    assert members.status_code == 200
    member = next(row for row in members.json() if row["email"] == "member@example.com")

    response = client.patch(f"/auth/org/members/{member['id']}", json={"is_active": False})
    assert response.status_code == 200
    assert response.json()["is_active"] is False


def test_org_cannot_remove_its_last_active_admin(client):
    register(client, "owner@example.com")
    login(client, "owner@example.com")
    owner = client.get("/auth/me").json()

    response = client.patch(f"/auth/org/members/{owner['id']}", json={"is_org_admin": False})
    assert response.status_code == 400
    assert "at least one active admin" in response.json()["detail"]

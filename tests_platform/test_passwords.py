"""Password change, forgot-password and reset."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from test_hardening import _client

PW = "first-password-123"


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    import opsec_platform.app.alerts as alerts

    monkeypatch.setattr(alerts, "send_mail", lambda to, subject, body: sent.append((to, subject, body)))
    return sent


def _smtp_client(monkeypatch, **env):
    return _client(monkeypatch, PLATFORM_SMTP_HOST="smtp.example.test", **env)


def _signed_in(client, email="owner@example.com", password=PW, org="Acme"):
    assert client.post("/auth/register", json={"email": email, "password": password, "org_name": org}).status_code == 201
    assert client.post("/auth/login", json={"email": email, "password": password}).status_code == 200
    return client


def _token_from(outbox):
    body = outbox[-1][2]
    return body.split("#reset=", 1)[1].split()[0]


# --- change -------------------------------------------------------------------

def test_change_password_requires_current_and_revokes_other_sessions(monkeypatch):
    client = _signed_in(_client(monkeypatch))
    from fastapi.testclient import TestClient
    other = TestClient(client.app)
    assert other.post("/auth/login", json={"email": "owner@example.com", "password": PW}).status_code == 200

    bad = client.post("/auth/password", json={"current_password": "nope-nope-nope", "new_password": "second-password-456"})
    assert bad.status_code == 400
    ok = client.post("/auth/password", json={"current_password": PW, "new_password": "second-password-456"})
    assert ok.status_code == 200 and ok.json()["other_sessions_revoked"] == 1

    assert client.get("/auth/me").status_code == 200          # this session survives
    assert other.get("/auth/me").status_code == 401           # the other one is gone
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": PW}).status_code == 401
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": "second-password-456"}).status_code == 200


def test_change_password_rejects_short_and_same_password(monkeypatch):
    client = _signed_in(_client(monkeypatch))
    assert client.post("/auth/password", json={"current_password": PW, "new_password": "short"}).status_code == 422
    assert client.post("/auth/password", json={"current_password": PW, "new_password": PW}).status_code == 400


def test_change_password_is_rate_limited(monkeypatch):
    client = _signed_in(_client(monkeypatch))
    for _ in range(5):
        client.post("/auth/password", json={"current_password": "wrong-wrong-1", "new_password": "another-password-9"})
    assert client.post("/auth/password", json={"current_password": PW, "new_password": "another-password-9"}).status_code == 429


def test_cli_access_token_cannot_change_password(monkeypatch):
    client = _signed_in(_client(monkeypatch))
    token = client.post("/auth/tokens", json={"name": "ci", "expires_in_days": 30}).json()["token"]
    from fastapi.testclient import TestClient
    bare = TestClient(client.app)
    r = bare.post("/auth/password", json={"current_password": PW, "new_password": "second-password-456"},
                  headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_sso_only_account_can_set_first_password_only_from_fresh_session(monkeypatch):
    client = _signed_in(_client(monkeypatch))
    import opsec_platform.app.dependencies as deps
    from opsec_platform.app.models import Session as SessionModel, User

    db = deps._SessionLocal()
    user = db.query(User).filter(User.email == "owner@example.com").first()
    user.hashed_password = None  # what an SSO-only account looks like
    db.commit()
    assert client.post("/auth/password", json={"new_password": "brand-new-pass-1"}).status_code == 200

    user = db.query(User).filter(User.email == "owner@example.com").first()
    user.hashed_password = None
    db.query(SessionModel).update({SessionModel.created_at: datetime.now(timezone.utc) - timedelta(hours=2)})
    db.commit()
    db.close()
    assert client.post("/auth/password", json={"new_password": "brand-new-pass-2"}).status_code == 403


# --- forgot / reset ------------------------------------------------------------

def test_forgot_password_is_disabled_without_smtp(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.delenv("PLATFORM_SMTP_HOST", raising=False)
    assert client.get("/health").json()["features"]["password_reset"] is False
    assert client.post("/auth/forgot-password", json={"email": "a@example.com"}).status_code == 503


def test_reset_flow_end_to_end_single_use(monkeypatch, outbox):
    client = _signed_in(_smtp_client(monkeypatch))
    assert client.get("/health").json()["features"]["password_reset"] is True

    r = client.post("/auth/forgot-password", json={"email": "Owner@Example.com"})
    assert r.status_code == 202
    assert outbox and outbox[-1][0] == "owner@example.com"
    assert "/login#reset=" in outbox[-1][2]  # fragment: never sent to (or logged by) a server
    token = _token_from(outbox)

    ok = client.post("/auth/reset-password", json={"token": token, "new_password": "reset-password-789"})
    assert ok.status_code == 200
    assert client.get("/auth/me").status_code == 401  # every session revoked
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": "reset-password-789"}).status_code == 200
    # The same link cannot be used twice.
    again = client.post("/auth/reset-password", json={"token": token, "new_password": "attacker-password-1"})
    assert again.status_code == 400


def test_forgot_password_does_not_reveal_accounts(monkeypatch, outbox):
    client = _signed_in(_smtp_client(monkeypatch))
    known = client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    unknown = client.post("/auth/forgot-password", json={"email": "ghost@example.com"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert [to for to, _, _ in outbox] == ["owner@example.com"]


def test_forgot_password_limits_mail_per_account_and_ip(monkeypatch, outbox):
    client = _signed_in(_smtp_client(monkeypatch))
    codes = [client.post("/auth/forgot-password", json={"email": "owner@example.com"}).status_code for _ in range(6)]
    assert codes[:5] == [202] * 5 and codes[5] == 429
    assert len(outbox) == 3


def test_reset_and_session_tokens_are_not_interchangeable(monkeypatch, outbox):
    client = _signed_in(_smtp_client(monkeypatch))
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    reset_token = _token_from(outbox)
    from fastapi.testclient import TestClient
    bare = TestClient(client.app)
    assert bare.get("/auth/me", headers={"Authorization": f"Bearer {reset_token}"}).status_code == 401

    session_token = client.cookies.get("opsec_session")
    assert session_token
    assert client.post("/auth/reset-password", json={"token": session_token, "new_password": "whatever-123"}).status_code == 400


def test_expired_and_tampered_reset_tokens_rejected(monkeypatch, outbox):
    client = _signed_in(_smtp_client(monkeypatch))
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    token = _token_from(outbox)
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    assert client.post("/auth/reset-password", json={"token": tampered, "new_password": "whatever-123"}).status_code == 400

    import opsec_platform.app.password_routes as pr
    monkeypatch.setattr(pr, "RESET_TTL_MINUTES", -1)
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    assert client.post("/auth/reset-password", json={"token": _token_from(outbox), "new_password": "whatever-123"}).status_code == 400

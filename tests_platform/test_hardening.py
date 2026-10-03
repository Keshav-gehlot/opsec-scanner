"""Regression tests for the full-project audit pass (2026-10-03)."""

import pytest
from fastapi.testclient import TestClient

JWT = "jwt-secret-for-tests-0123456789abcdefghijklmn"


def _client(monkeypatch, **env):
    base = {
        "PLATFORM_JWT_SECRET": JWT,
        "PLATFORM_COOKIE_SECURE": "false",
        "PLATFORM_DATABASE_URL": "sqlite:///:memory:",
    }
    base.update(env)
    for key in ("PLATFORM_BASE_URL", "PLATFORM_BOOTSTRAP_ADMIN_EMAIL", "PLATFORM_BOOTSTRAP_ADMIN_PASSWORD",
                "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "PLATFORM_ALLOWED_ORIGINS"):
        monkeypatch.delenv(key, raising=False)
    for key, value in base.items():
        monkeypatch.setenv(key, value)
    import opsec_platform.app.dependencies as deps

    deps._engine = None
    deps._SessionLocal = None
    from opsec_platform.app.main import create_app

    return TestClient(create_app())


def _register(client, email, org, password="testpass123", headers=None):
    return client.post("/auth/register", json={"email": email, "password": password, "org_name": org},
                       headers=headers or {})


# --- client IP behind Vercel -------------------------------------------------

def _vercel(ip):
    return {"x-vercel-id": "bom1::abc", "x-vercel-forwarded-for": ip}


def test_login_ip_limit_is_per_real_client_behind_vercel(monkeypatch):
    client = _client(monkeypatch, PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS="3", PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS="100")
    for i in range(3):
        r = client.post("/auth/login", json={"email": f"nobody{i}@example.com", "password": "x"},
                        headers=_vercel("198.51.100.7"))
        assert r.status_code == 401
    blocked = client.post("/auth/login", json={"email": "nobody9@example.com", "password": "x"},
                          headers=_vercel("198.51.100.7"))
    assert blocked.status_code == 429
    # A different visitor arriving through the same Vercel edge is unaffected.
    other = client.post("/auth/login", json={"email": "nobody9@example.com", "password": "x"},
                        headers=_vercel("203.0.113.9"))
    assert other.status_code == 401


def test_vercel_header_ignored_without_vercel_marker_and_when_invalid():
    from starlette.requests import Request
    from opsec_platform.app.client_ip import client_ip

    def req(headers):
        scope = {"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                 "client": ("10.0.0.5", 1234)}
        return Request(scope)

    assert client_ip(req({"x-vercel-forwarded-for": "1.2.3.4"})) == "10.0.0.5"
    assert client_ip(req({"x-vercel-id": "x", "x-vercel-forwarded-for": "not-an-ip"})) == "10.0.0.5"
    assert client_ip(req({"x-vercel-id": "x", "x-vercel-forwarded-for": "1.2.3.4, 5.6.7.8"})) == "1.2.3.4"


def test_unknown_email_rate_limit_does_not_bleed_across_similar_addresses(monkeypatch):
    client = _client(monkeypatch, PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS="2", PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS="100")
    for _ in range(2):
        client.post("/auth/login", json={"email": "a_b@example.com", "password": "x"})
    assert client.post("/auth/login", json={"email": "a_b@example.com", "password": "x"}).status_code == 429
    # "_" must not act as a LIKE wildcard, and a prefix must not match.
    assert client.post("/auth/login", json={"email": "axb@example.com", "password": "x"}).status_code == 401
    assert client.post("/auth/login", json={"email": "a_b@example.co", "password": "x"}).status_code == 401


# --- registration throttling ---------------------------------------------------

def test_registration_attempts_are_rate_limited_per_ip(monkeypatch):
    client = _client(monkeypatch, PLATFORM_REGISTER_RATE_LIMIT_ATTEMPTS="3")
    assert _register(client, "one@example.com", "Org One").status_code == 201
    assert _register(client, "one@example.com", "Org One").status_code == 409  # counted too
    assert _register(client, "two@example.com", "Org Two").status_code == 201
    assert _register(client, "three@example.com", "Org Three").status_code == 429
    # Another visitor (behind Vercel) can still register.
    assert _register(client, "four@example.com", "Org Four", headers=_vercel("203.0.113.50")).status_code == 201


# --- bootstrap admin -------------------------------------------------------------

def _login(client, email, password):
    client.cookies.clear()
    return client.post("/auth/login", json={"email": email, "password": password}).status_code


def test_weak_bootstrap_password_is_refused_in_production(monkeypatch):
    from opsec_platform.app.bootstrap import run_bootstrap_admin
    import opsec_platform.app.dependencies as deps

    _client(monkeypatch)
    assert run_bootstrap_admin(deps._SessionLocal, "admin@example.com", "admin12345", secure=True) == "weak-skipped"
    from opsec_platform.app.models import User
    db = deps._SessionLocal()
    assert db.query(User).filter(User.email == "admin@example.com").first() is None
    db.close()


def test_existing_admin_with_weak_password_is_locked(monkeypatch):
    from opsec_platform.app.bootstrap import run_bootstrap_admin
    import opsec_platform.app.dependencies as deps

    client = _client(monkeypatch)
    # Created by the old code path (no policy) ...
    assert run_bootstrap_admin(deps._SessionLocal, "admin@example.com", "admin12345", secure=False) == "created"
    assert _login(client, "admin@example.com", "admin12345") == 200
    # ... then the hardened startup in production disables that password.
    assert run_bootstrap_admin(deps._SessionLocal, "admin@example.com", "admin12345", secure=True) == "weak-locked"
    assert _login(client, "admin@example.com", "admin12345") == 401


def test_strong_bootstrap_password_rotates(monkeypatch):
    from opsec_platform.app.bootstrap import run_bootstrap_admin
    import opsec_platform.app.dependencies as deps

    client = _client(monkeypatch)
    first, second = "Correct-Horse-Battery-1", "Another-Strong-Passphrase-2"
    assert run_bootstrap_admin(deps._SessionLocal, "root@example.com", first, secure=True) == "created"
    assert run_bootstrap_admin(deps._SessionLocal, "root@example.com", first, secure=True) == "unchanged"
    assert run_bootstrap_admin(deps._SessionLocal, "root@example.com", second, secure=True) == "rotated"
    assert _login(client, "root@example.com", first) == 401
    assert _login(client, "root@example.com", second) == 200


@pytest.mark.parametrize("password", ["short", "rootrootroot12", "aaaaaaaaaaaaaa"])
def test_bootstrap_password_policy(password):
    from opsec_platform.app.bootstrap import bootstrap_password_problem

    assert bootstrap_password_problem("root@example.com", password) is not None


# --- cross-site request guard ------------------------------------------------------

def test_cross_site_post_is_refused(monkeypatch):
    client = _client(monkeypatch)
    body = {"email": "x@example.com", "password": "x"}
    assert client.post("/auth/login", json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/auth/login", json=body, headers={"Origin": "null"}).status_code == 403
    # Same-origin browser requests and Origin-less (CLI) requests are untouched.
    assert client.post("/auth/login", json=body, headers={"Origin": "http://testserver"}).status_code == 401
    assert client.post("/auth/login", json=body).status_code == 401


def test_configured_public_origin_is_trusted(monkeypatch):
    client = _client(monkeypatch, PLATFORM_BASE_URL="https://app.example.com")
    r = client.post("/auth/login", json={"email": "x@example.com", "password": "x"},
                    headers={"Origin": "https://app.example.com"})
    assert r.status_code == 401


def test_request_id_is_bounded(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/health/live", headers={"X-Request-ID": "a" * 500})
    assert len(r.headers["X-Request-ID"]) == 36


# --- CLI ------------------------------------------------------------------------

@pytest.mark.parametrize("ref", ["--output=/tmp/x", "-n1", "", " origin/main", "a\nb"])
def test_since_ref_rejects_option_like_values(ref):
    from opsec_scanner.engines.git_engine import validate_ref

    with pytest.raises(ValueError):
        validate_ref(ref)


def test_since_ref_accepts_normal_refs():
    from opsec_scanner.engines.git_engine import validate_ref

    for ref in ("origin/main", "HEAD~3", "v1.2.0", "abc1234"):
        assert validate_ref(ref) == ref

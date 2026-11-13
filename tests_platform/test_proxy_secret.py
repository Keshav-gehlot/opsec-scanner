"""Audit S1/S2 (2026-11-13): forged Vercel forwarding headers sent straight
to the public Render origin must not let a client rotate its rate-limit IP."""

from __future__ import annotations

from test_hardening import _client

SECRET = "proxy-secret-for-tests-0123456789abcdef"


def _forged(ip):
    return {"x-vercel-id": "bom1::forged", "x-vercel-forwarded-for": ip}


def _proxied(ip):
    return {**_forged(ip), "x-opsec-proxy-secret": SECRET}


def _spray(client, headers_for, n=6):
    return [
        client.post("/auth/login", json={"email": f"victim{i}@example.com", "password": "wrong-password"},
                    headers=headers_for(i)).status_code
        for i in range(n)
    ]


def test_forged_forwarded_for_without_secret_is_ignored(monkeypatch):
    client = _client(monkeypatch, PLATFORM_PROXY_SECRET=SECRET,
                     PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS="3", PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS="100")
    codes = _spray(client, lambda i: _forged(f"203.0.113.{i}"))
    # Rotating fake addresses no longer helps: the real peer is counted.
    assert codes[:3] == [401, 401, 401] and set(codes[3:]) == {429}


def test_wrong_secret_is_treated_as_forged(monkeypatch):
    client = _client(monkeypatch, PLATFORM_PROXY_SECRET=SECRET,
                     PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS="3", PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS="100")
    codes = _spray(client, lambda i: {**_forged(f"203.0.113.{i}"), "x-opsec-proxy-secret": "guess"})
    assert set(codes[3:]) == {429}


def test_genuine_proxy_keeps_per_visitor_buckets(monkeypatch):
    client = _client(monkeypatch, PLATFORM_PROXY_SECRET=SECRET,
                     PLATFORM_LOGIN_IP_RATE_LIMIT_ATTEMPTS="3", PLATFORM_LOGIN_RATE_LIMIT_ATTEMPTS="100")
    # Different real visitors behind the same Vercel egress are not lumped together.
    assert set(_spray(client, lambda i: _proxied(f"198.51.100.{i}"))) == {401}
    # The same real visitor is still limited.
    assert _spray(client, lambda i: _proxied("198.51.100.200"), n=4)[-1] == 429


def test_require_proxy_secret_blocks_direct_origin_access(monkeypatch):
    client = _client(monkeypatch, PLATFORM_PROXY_SECRET=SECRET, PLATFORM_REQUIRE_PROXY_SECRET="true")
    assert client.get("/health").status_code == 403
    assert client.post("/auth/login", json={"email": "a@example.com", "password": "x"}).status_code == 403
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 200  # Render's health check path
    assert client.get("/health", headers={"x-opsec-proxy-secret": SECRET}).status_code == 200


def test_require_without_secret_does_not_lock_everyone_out(monkeypatch):
    client = _client(monkeypatch, PLATFORM_REQUIRE_PROXY_SECRET="true")
    assert client.get("/health").status_code == 200


def test_health_reports_media_tool_availability_and_package_version(monkeypatch):
    from importlib.metadata import version

    body = _client(monkeypatch).get("/health").json()
    assert body["version"] == version("opsec-scanner")
    assert isinstance(body["scanner"]["exiftool_available"], bool)
    assert isinstance(body["scanner"]["ocr_available"], bool)


def test_health_reports_whether_request_came_through_proxy(monkeypatch):
    client = _client(monkeypatch, PLATFORM_PROXY_SECRET=SECRET)
    assert client.get("/health").json()["proxy_verified"] is False
    assert client.get("/health", headers={"x-opsec-proxy-secret": SECRET}).json()["proxy_verified"] is True

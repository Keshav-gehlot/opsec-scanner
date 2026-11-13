"""
Best-effort originating client IP, for rate limiting and audit logs ONLY.

Never use this for authentication or authorization: every forwarding header
can be forged by a client that reaches Render directly.

Production topology: browser -> Vercel (rewrite) -> Render -> app.
Requests proxied by Vercel reach the app from one of Vercel's shared egress
addresses, so keying the login limiter on request.client.host lumps every
Vercel user into one bucket. Vercel passes the real visitor address in
`x-vercel-forwarded-for`.

The Render origin (*.onrender.com) is publicly reachable, though, so any
client can send `x-vercel-id` / `x-vercel-forwarded-for` itself and rotate a
fake address on every request, defeating the per-IP limiter (audit S1,
2026-11-13). When PLATFORM_PROXY_SECRET is set, the forwarded address is
trusted only if the request also carries `x-opsec-proxy-secret` with that
value — added by Vercel Routing Middleware (middleware.js) from a Vercel
environment variable, never present in the repository. Without the secret
the direct peer address is used, which an attacker cannot forge.

PLATFORM_PROXY_SECRET unset keeps the previous behaviour (header trusted on
the x-vercel-id marker alone) so a deployment never locks everyone into one
bucket before both sides are configured; a warning is logged at startup.
"""

from __future__ import annotations

import hmac
import ipaddress
import os

from fastapi import Request

PROXY_SECRET_HEADER = "x-opsec-proxy-secret"


def proxy_secret() -> str:
    return os.environ.get("PLATFORM_PROXY_SECRET", "").strip()


def proxy_secret_required() -> bool:
    return os.environ.get("PLATFORM_REQUIRE_PROXY_SECRET", "false").strip().lower() == "true"


def has_valid_proxy_secret(request: Request) -> bool:
    secret = proxy_secret()
    supplied = request.headers.get(PROXY_SECRET_HEADER, "")
    return bool(secret) and bool(supplied) and hmac.compare_digest(supplied.encode(), secret.encode())


def _valid_ip(value: str) -> str | None:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _trust_forwarded(request: Request) -> bool:
    if not request.headers.get("x-vercel-id"):
        return False
    if proxy_secret():
        return has_valid_proxy_secret(request)
    return True


def client_ip(request: Request) -> str:
    if _trust_forwarded(request):
        forwarded = request.headers.get("x-vercel-forwarded-for", "")
        first = _valid_ip(forwarded.split(",")[0]) if forwarded else None
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def client_meta(request: Request) -> tuple[str, str]:
    """(client ip, user agent) with the user agent bounded for storage."""
    return client_ip(request), request.headers.get("user-agent", "unknown")[:512]

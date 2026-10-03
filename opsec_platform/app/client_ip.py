"""
Best-effort originating client IP, for rate limiting and audit logs ONLY.

Never use this for authentication or authorization: every forwarding header
can be forged by a client that reaches Render directly.

Production topology: browser -> Vercel (external rewrite) -> Render -> app.
Render's access logs show that requests proxied by Vercel reach the app with
one of Vercel's shared egress addresses as request.client.host. Keying the
login limiter on that address lumps every Vercel user into one bucket, so a
handful of failed logins by anyone locks everyone out. Vercel passes the
real visitor address in `x-vercel-forwarded-for`; prefer it when the request
carries Vercel's `x-vercel-id` marker.
"""

from __future__ import annotations

import ipaddress

from fastapi import Request


def _valid_ip(value: str) -> str | None:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    if request.headers.get("x-vercel-id"):
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

"""
Outbound HTTP for the monitoring modules, hardened against SSRF.

Every request the platform makes on a user's behalf (crawling a verified
site, checking a /.well-known file, posting to a webhook) goes through
``safe_request``:

- only http/https, no credentials in the URL, ports 80/443 unless the
  caller explicitly allows others;
- the host is resolved once and EVERY address must be globally routable
  (no loopback, private, link-local/metadata, CGNAT, multicast, reserved);
- the connection is made to that vetted IP (Host header + TLS SNI keep the
  original name), so a DNS answer cannot change between the check and the
  connect (DNS rebinding);
- redirects are followed manually, re-validating each hop;
- response bodies are capped and requests time out.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

USER_AGENT = "OPSEC-Scanner-Monitor/0.4 (+self-audit; owner-verified targets only)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


class UnsafeTarget(ValueError):
    """The URL points somewhere the platform must not connect to."""


@dataclass
class SafeResponse:
    url: str
    status_code: int
    headers: dict
    content: bytes
    truncated: bool

    @property
    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self):
        import json

        return json.loads(self.content.decode("utf-8", errors="replace"))


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_global) and not ip.is_multicast and not ip.is_reserved


def resolve_public(host: str, port: int) -> list[str]:
    """All addresses for host; raises UnsafeTarget unless every one is public."""
    if not host:
        raise UnsafeTarget("Missing host.")
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeTarget(f"Could not resolve {host}.") from None
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeTarget(f"Could not resolve {host}.")
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeTarget(f"{host} resolves to a non-public address; refusing to connect.")
    return addresses


def validate_url(url: str, allowed_ports: tuple[int, ...] = (80, 443)) -> tuple[str, str, int]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTarget("Only http(s) URLs are allowed.")
    if parsed.username or parsed.password:
        raise UnsafeTarget("URLs with credentials are not allowed.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeTarget("URL has no host.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in allowed_ports:
        raise UnsafeTarget(f"Port {port} is not allowed.")
    return parsed.scheme, host, port


def safe_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    json_body=None,
    data: bytes | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = 3,
    allowed_ports: tuple[int, ...] = (80, 443),
    resolver=resolve_public,
    verify=True,
) -> SafeResponse:
    # Behind an outbound proxy the proxy performs the connection (and DNS),
    # so the vetted IP cannot be pinned; the resolution check still applies.
    via_proxy = any(os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"))
    current = url
    for _ in range(max_redirects + 1):
        scheme, host, port = validate_url(current, allowed_ports)
        address = resolver(host, port)[0]
        parsed = urlparse(current)
        if via_proxy:
            target, extensions = current, {}
            request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
        else:
            ip_host = f"[{address}]" if ":" in address else address
            target = parsed._replace(netloc=f"{ip_host}:{port}").geturl()
            request_headers = {"User-Agent": USER_AGENT, "Host": parsed.netloc.split("@")[-1], **(headers or {})}
            extensions = {"sni_hostname": host} if scheme == "https" else {}
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=verify, trust_env=via_proxy) as client:
            request = client.build_request(method, target, headers=request_headers, json=json_body,
                                           content=data, extensions=extensions)
            response = client.send(request, stream=True)
            try:
                if response.is_redirect and method.upper() in ("GET", "HEAD"):
                    location = response.headers.get("location")
                    if not location:
                        raise UnsafeTarget("Redirect without a location.")
                    current = urljoin(current, location)
                    continue
                chunks, size, truncated = [], 0, False
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        chunks.append(chunk[: max(0, max_bytes - (size - len(chunk)))])
                        truncated = True
                        break
                    chunks.append(chunk)
                return SafeResponse(
                    url=current, status_code=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    content=b"".join(chunks), truncated=truncated,
                )
            finally:
                response.close()
    raise UnsafeTarget("Too many redirects.")


def api_get(url: str, *, headers: dict | None = None, params: dict | None = None, timeout: float = DEFAULT_TIMEOUT):
    """GET for fixed, well-known public APIs (GitHub, crt.sh, RDAP, DoH...).

    The host is a constant chosen by this codebase, never user input, so a
    normal client is fine; the size cap still applies."""
    with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        response = client.get(url, headers=headers, params=params)
        if len(response.content) > DEFAULT_MAX_BYTES * 4:
            raise ValueError("Response too large.")
        return response

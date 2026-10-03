"""
Ownership verification for monitored targets.

The monitoring modules collect public data about a target, which is only
appropriate for things the user controls. Each target kind has a proof:

  domain         DNS TXT record  opsec-scanner-verify=<token>  on the domain,
                 or the token served at https://<domain>/.well-known/opsec-scanner.txt
  url            the URL's host must be a domain the user has verified
  email          must be the address of the signed-in account (proven by
                 password registration or the SSO provider's verified email)
  github_handle  a public gist owned by the handle whose description
                 contains the token
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urlparse

from opsec_platform.app.osint import net

TXT_PREFIX = "opsec-scanner-verify="
WELL_KNOWN_PATH = "/.well-known/opsec-scanner.txt"
KINDS = ("domain", "url", "email", "github_handle")

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{3,255}$")


class TargetError(ValueError):
    pass


def new_token() -> str:
    return secrets.token_urlsafe(18)


def normalize(kind: str, value: str) -> str:
    value = (value or "").strip()
    if kind == "domain":
        value = value.lower().rstrip(".")
        if value.startswith(("http://", "https://")):
            value = urlparse(value).hostname or ""
        if value.startswith("www."):
            value = value[4:]
        if not _DOMAIN_RE.match(value):
            raise TargetError("Enter a domain like example.com.")
        return value
    if kind == "url":
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise TargetError("Enter a full http(s) URL.")
        if parsed.username or parsed.password or (parsed.port and parsed.port not in (80, 443)):
            raise TargetError("URLs with credentials or non-standard ports are not supported.")
        return parsed._replace(fragment="").geturl()[:500]
    if kind == "email":
        value = value.lower()
        if not _EMAIL_RE.match(value):
            raise TargetError("Enter a valid email address.")
        return value
    if kind == "github_handle":
        value = value.lstrip("@")
        if not _HANDLE_RE.match(value):
            raise TargetError("Enter a GitHub username.")
        return value
    raise TargetError("Unknown target type.")


def url_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def domain_covers(verified_domain: str, host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == verified_domain or host.endswith("." + verified_domain)


def check_dns_txt(domain: str, token: str, resolver=None) -> bool:
    import dns.resolver

    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = 6.0
    try:
        answers = resolver.resolve(domain, "TXT")
    except Exception:
        return False
    expected = TXT_PREFIX + token
    for record in answers:
        text = b"".join(record.strings).decode("utf-8", "replace").strip()
        if text == expected:
            return True
    return False


def check_well_known(domain: str, token: str, fetch=net.safe_request) -> bool:
    for scheme in ("https", "http"):
        try:
            response = fetch("GET", f"{scheme}://{domain}{WELL_KNOWN_PATH}", max_bytes=4096, timeout=8)
        except Exception:
            continue
        if response.status_code == 200 and token in response.text:
            return True
    return False


def check_github_gist(handle: str, token: str, api_get=net.api_get) -> bool:
    try:
        response = api_get(f"https://api.github.com/users/{handle}/gists", params={"per_page": 30})
    except Exception:
        return False
    if response.status_code != 200:
        return False
    for gist in response.json():
        owner = (gist.get("owner") or {}).get("login", "")
        if owner.lower() == handle.lower() and token in (gist.get("description") or ""):
            return True
    return False


def instructions(kind: str, value: str, token: str) -> dict:
    if kind == "domain":
        return {
            "methods": [
                {"method": "dns_txt", "summary": f"Add a TXT record on {value}", "record": f"{TXT_PREFIX}{token}"},
                {"method": "well_known", "summary": f"Serve the token at https://{value}{WELL_KNOWN_PATH}", "content": token},
            ]
        }
    if kind == "url":
        return {"methods": [{"method": "domain", "summary": f"Verify the domain {url_domain(value)} first; URLs on it are then covered."}]}
    if kind == "email":
        return {"methods": [{"method": "account_email", "summary": "Only the email address of your signed-in account can be monitored."}]}
    return {"methods": [{"method": "gist", "summary": f"Create a public gist as @{value} whose description contains this token", "content": token}]}

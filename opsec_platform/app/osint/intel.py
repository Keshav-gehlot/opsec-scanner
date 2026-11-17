"""
Extended collection modules (audit gap list, 2026-11-14).

  search_dorks       search-engine results about a verified domain/email,
                     through official APIs only (Brave Search API, or your
                     own SearXNG instance, which queries Google/Bing/
                     DuckDuckGo itself). Scraping search pages breaks their
                     terms; Google's Custom Search JSON API is closed to new
                     customers and ends on 2027-01-01, so it is not used.
  username_presence  where else a verified GitHub handle is registered,
                     using each platform's own public API (identity linking
                     across sites is an OPSEC exposure in itself).
  leak_index         pastes, public/private leak indexes and darknet
                     (Tor/I2P) mentions of a verified email or domain via the
                     Intelligence X API. Metadata only: item names, buckets
                     and dates. Leaked file contents are never downloaded.
  ip_enrichment      ASN (Team Cymru DNS) and GeoIP (ipinfo.io) per IP.
  threat_intel       AlienVault OTX pulses and AbuseIPDB reports for the
                     domain and its IPs.

Every source is optional and keyed by an environment variable; a missing key
adds a note instead of failing the scan. All hosts are constants chosen here,
except PLATFORM_SEARXNG_URL, which goes through net.safe_request (public
addresses only, no redirects to private ranges).
"""

from __future__ import annotations

import ipaddress
import os
import time
from typing import Any, Callable
from urllib.parse import quote, urlparse

import httpx

from opsec_scanner.models import RawFinding, SourceType

from opsec_platform.app.osint import net
from opsec_platform.app.osint.collectors import CollectorResult, DirectFinding, _lines_to_raw
from opsec_platform.app.osint.verification import domain_covers

# ---------------------------------------------------------------------------
# Search engines
# ---------------------------------------------------------------------------

SENSITIVE_EXTENSIONS = {"env", "sql", "log", "bak", "backup", "old", "conf", "cfg", "ini", "key", "pem", "dump",
                        "sqlite", "db", "swp", "git", "htpasswd"}
DOCUMENT_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv"}
MAX_RESULTS_PER_QUERY = 20


def domain_dorks(domain: str) -> list[tuple[str, str]]:
    return [
        ("sensitive_files", f"site:{domain} (ext:env OR ext:sql OR ext:log OR ext:bak OR ext:conf OR ext:pem OR ext:dump)"),
        ("directory_listing", f'site:{domain} intitle:"index of"'),
        ("documents", f"site:{domain} (ext:pdf OR ext:docx OR ext:xlsx OR ext:pptx OR ext:csv)"),
        ("external_mentions", f'"@{domain}" -site:{domain}'),
    ]


def email_dorks(email: str) -> list[tuple[str, str]]:
    return [("external_mentions", f'"{email}"')]


def _brave(query: str, key: str, api_get) -> list[dict]:
    response = api_get("https://api.search.brave.com/res/v1/web/search",
                       params={"q": query, "count": MAX_RESULTS_PER_QUERY, "safesearch": "off"},
                       headers={"X-Subscription-Token": key, "Accept": "application/json"}, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"Brave Search returned HTTP {response.status_code}")
    return [{"url": r.get("url", ""), "title": r.get("title", ""), "snippet": r.get("description", "")}
            for r in (response.json().get("web") or {}).get("results", [])]


def _searxng(query: str, base: str, request) -> list[dict]:
    url = base.rstrip("/") + "/search?" + httpx.QueryParams({"q": query, "format": "json"}).__str__()
    response = request("GET", url, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"SearXNG returned HTTP {response.status_code} (enable the json format in settings.yml)")
    return [{"url": r.get("url", ""), "title": r.get("title", ""), "snippet": r.get("content", "")}
            for r in response.json().get("results", [])[:MAX_RESULTS_PER_QUERY]]


def _search_provider(api_get, request):
    key = os.environ.get("PLATFORM_BRAVE_SEARCH_API_KEY", "").strip()
    if key:
        return "brave", lambda q: _brave(q, key, api_get)
    base = os.environ.get("PLATFORM_SEARXNG_URL", "").strip()
    if base:
        return "searxng", lambda q: _searxng(q, base, request)
    return None, None


def _ext(url: str) -> str:
    path = urlparse(url).path.lower()
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1] if "." in name else ""


def search_dorks(kind: str, value: str, verified_domains: list[str], api_get=net.api_get,
                 request=net.safe_request) -> CollectorResult:
    result = CollectorResult()
    provider, search = _search_provider(api_get, request)
    if search is None:
        result.notes.append("Search-engine checks skipped (set PLATFORM_BRAVE_SEARCH_API_KEY, or PLATFORM_SEARXNG_URL "
                            "for your own SearXNG instance).")
        return result
    dorks = domain_dorks(value) if kind == "domain" else email_dorks(value)
    hits: list[dict] = []
    for label, query in dorks:
        try:
            items = search(query)
        except Exception as exc:
            result.notes.append(f"Search '{label}' failed: {exc if isinstance(exc, RuntimeError) else type(exc).__name__}.")
            continue
        for item in items:
            url, host = item["url"], (urlparse(item["url"]).hostname or "").lower()
            if not url.startswith(("http://", "https://")):
                continue
            own = any(domain_covers(d, host) for d in verified_domains) if host else False
            hits.append({"query": label, "url": url, "title": item["title"][:200], "own_site": own})
            origin = f"search:{provider}:{url}"
            text = f"{item['title']}\n{item['snippet']}"
            result.raw.extend(_lines_to_raw(text, origin, SourceType.SEARCH_RESULT, max_lines=10))
            ext = _ext(url)
            if own and (ext in SENSITIVE_EXTENSIONS or label == "sensitive_files" and ext and ext not in DOCUMENT_EXTENSIONS):
                result.direct.append(DirectFinding("search_indexed_sensitive_file", url, origin,
                                                   f"Search engines index {url}"))
            elif own and label == "directory_listing" and "index of" in item["title"].lower():
                result.direct.append(DirectFinding("search_indexed_directory_listing", url, origin, item["title"][:200]))
            elif label == "external_mentions" and not own:
                result.direct.append(DirectFinding("search_external_mention", f"{value} on {host}", origin,
                                                   item["title"][:200]))
    result.intel["search"] = {"provider": provider, "results": hits[:100]}
    return result


# ---------------------------------------------------------------------------
# Cross-platform username presence (official public APIs only)
# ---------------------------------------------------------------------------

def _found_if_status(ok: int = 200, missing: tuple[int, ...] = (404,)):
    def judge(response) -> bool | None:
        if response.status_code == ok:
            return True
        if response.status_code in missing:
            return False
        return None
    return judge


def _found_if_json(predicate):
    def judge(response) -> bool | None:
        if response.status_code != 200:
            return False if response.status_code == 404 else None
        try:
            return bool(predicate(response.json()))
        except Exception:
            return None
    return judge


# name -> (api url template, public profile url template, judge)
PLATFORMS: dict[str, tuple[str, str, Callable[[Any], bool | None]]] = {
    "GitLab": ("https://gitlab.com/api/v4/users?username={u}", "https://gitlab.com/{u}",
               _found_if_json(lambda d: isinstance(d, list) and len(d) > 0)),
    "Codeberg": ("https://codeberg.org/api/v1/users/{u}", "https://codeberg.org/{u}", _found_if_status()),
    "Bitbucket": ("https://api.bitbucket.org/2.0/workspaces/{u}", "https://bitbucket.org/{u}", _found_if_status()),
    "Docker Hub": ("https://hub.docker.com/v2/users/{u}/", "https://hub.docker.com/u/{u}", _found_if_status()),
    "npm": ("https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "https://www.npmjs.com/~{u}", _found_if_status()),
    "PyPI": ("https://pypi.org/user/{u}/", "https://pypi.org/user/{u}/", _found_if_status()),
    "Keybase": ("https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics", "https://keybase.io/{u}",
                _found_if_json(lambda d: any(d.get("them") or []))),
    "Hacker News": ("https://hacker-news.firebaseio.com/v0/user/{u}.json", "https://news.ycombinator.com/user?id={u}",
                    _found_if_json(lambda d: d is not None)),
    "DEV": ("https://dev.to/api/users/by_username?url={u}", "https://dev.to/{u}", _found_if_status()),
    "Reddit": ("https://www.reddit.com/user/{u}/about.json", "https://www.reddit.com/user/{u}", _found_if_status()),
    "Mastodon (mastodon.social)": ("https://mastodon.social/api/v1/accounts/lookup?acct={u}",
                                   "https://mastodon.social/@{u}", _found_if_status()),
    "Lobsters": ("https://lobste.rs/~{u}.json", "https://lobste.rs/~{u}", _found_if_status()),
}
_USERNAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def username_presence(handle: str, api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    if not handle or len(handle) > 39 or set(handle) - _USERNAME_OK:
        result.notes.append("Username check skipped: unsupported characters in the handle.")
        return result
    found, unknown = [], []
    for name, (api, profile, judge) in PLATFORMS.items():
        u = quote(handle, safe="")
        try:
            verdict = judge(api_get(api.format(u=u), timeout=10))
        except Exception:
            verdict = None
        if verdict:
            url = profile.format(u=u)
            found.append({"platform": name, "url": url})
            result.direct.append(DirectFinding("handle_reused_on_platform", f"{handle} on {name}", f"profile:{url}",
                                               f"An account named '{handle}' exists on {name}: {url}"))
        elif verdict is None:
            unknown.append(name)
    result.intel["platforms"] = {"handle": handle, "found": found, "unknown": unknown,
                                 "checked": len(PLATFORMS)}
    if unknown:
        result.notes.append("Username check inconclusive (rate limit or error) on: " + ", ".join(unknown) + ".")
    return result


# ---------------------------------------------------------------------------
# Paste / leak / darknet index (Intelligence X; metadata only)
# ---------------------------------------------------------------------------

LEAK_BUCKET_RULES = (("pastes", "paste_exposure"), ("darknet", "darkweb_mention"), ("leaks", "leak_index_exposure"))


def _bucket_rule(bucket: str) -> str | None:
    for prefix, rule in LEAK_BUCKET_RULES:
        if bucket == prefix or bucket.startswith(prefix + "."):
            return rule
    return None


def leak_index(term: str, client: httpx.Client | None = None, poll_seconds: float = 1.0, polls: int = 8) -> CollectorResult:
    result = CollectorResult()
    key = os.environ.get("PLATFORM_INTELX_API_KEY", "").strip()
    if not key:
        result.notes.append("Paste, leak and darknet index skipped (set PLATFORM_INTELX_API_KEY; free keys at intelx.io).")
        return result
    base = os.environ.get("PLATFORM_INTELX_API_URL", "https://free.intelx.io").strip().rstrip("/")
    if urlparse(base).hostname not in ("free.intelx.io", "2.intelx.io", "public.intelx.io"):
        result.notes.append("PLATFORM_INTELX_API_URL must be free.intelx.io, 2.intelx.io or public.intelx.io.")
        return result
    headers = {"x-key": key, "User-Agent": net.USER_AGENT}
    owns = client is None
    client = client or httpx.Client(timeout=25, follow_redirects=False)
    records: list[dict] = []
    try:
        start = client.post(f"{base}/intelligent/search", headers=headers, json={
            "term": term, "buckets": [], "lookuplevel": 0, "maxresults": 100, "timeout": 10,
            "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": []})
        if start.status_code != 200:
            result.notes.append(f"Intelligence X search returned HTTP {start.status_code}.")
            return result
        search_id = start.json().get("id")
        for _ in range(polls):
            page = client.get(f"{base}/intelligent/search/result", headers=headers,
                              params={"id": search_id, "limit": 100})
            if page.status_code != 200:
                break
            body = page.json()
            records.extend(body.get("records") or [])
            if body.get("status") in (1, 2):  # 1 = finished, 2 = no more results / not found
                break
            time.sleep(poll_seconds)
        try:
            client.get(f"{base}/intelligent/search/terminate", headers=headers, params={"id": search_id})
        except Exception:
            pass
    except Exception as exc:
        result.notes.append(f"Intelligence X lookup failed ({type(exc).__name__}).")
        return result
    finally:
        if owns:
            client.close()

    summary: dict[str, int] = {}
    seen = set()
    for rec in records:
        bucket = str(rec.get("bucket") or "")
        rule = _bucket_rule(bucket)
        if rule is None:
            continue
        summary[bucket] = summary.get(bucket, 0) + 1
        sid = rec.get("systemid") or rec.get("storageid") or rec.get("name")
        if sid in seen or len(seen) >= 50:
            continue
        seen.add(sid)
        name = str(rec.get("name") or "untitled")[:120]
        date = str(rec.get("date") or rec.get("added") or "")[:10]
        result.direct.append(DirectFinding(rule, f"{term} in {bucket}: {name}", f"intelx:{bucket}:{sid}",
                                           f"{date or 'undated'} · {bucket} · https://intelx.io/?did={sid}"))
    result.intel["leak_index"] = {"term": term, "buckets": summary, "records": len(records)}
    return result


# ---------------------------------------------------------------------------
# IP enrichment: ASN (Team Cymru DNS) + GeoIP (ipinfo.io)
# ---------------------------------------------------------------------------

def _cymru_origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def asn_lookup(ip: str, dns_lookup) -> dict:
    """Team Cymru's DNS interface: '15169 | 8.8.8.0/24 | US | arin | 2023-12-28'."""
    out: dict = {}
    try:
        txt = dns_lookup(_cymru_origin_name(ip), "TXT")
    except ValueError:
        return out
    if not txt:
        return out
    parts = [p.strip() for p in txt[0].split("|")]
    if parts and parts[0]:
        asn = parts[0].split()[0]
        out = {"asn": f"AS{asn}", "prefix": parts[1] if len(parts) > 1 else None,
               "asn_country": parts[2] if len(parts) > 2 else None}
        names = dns_lookup(f"AS{asn}.asn.cymru.com", "TXT")
        if names:
            fields = [p.strip() for p in names[0].split("|")]
            out["asn_name"] = fields[-1] if fields else None
    return out


def geoip_lookup(ip: str, api_get) -> dict:
    token = os.environ.get("PLATFORM_IPINFO_TOKEN", "").strip()
    try:
        response = api_get(f"https://ipinfo.io/{quote(ip)}/json", params={"token": token} if token else None, timeout=10)
    except Exception:
        return {}
    if response.status_code != 200:
        return {}
    data = response.json()
    return {k: data.get(k) for k in ("city", "region", "country", "org") if data.get(k)}


def ip_enrichment(ips: list[dict], dns_lookup, api_get=net.api_get) -> None:
    """Adds asn/asn_name/prefix and city/region/country/org to each {"ip": ...} in place."""
    for info in ips:
        ip = info.get("ip", "")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        info.update(asn_lookup(ip, dns_lookup))
        geo = geoip_lookup(ip, api_get)
        if geo:
            info["geo"] = geo


# ---------------------------------------------------------------------------
# Threat intelligence: AlienVault OTX + AbuseIPDB
# ---------------------------------------------------------------------------

ABUSE_SCORE_THRESHOLD = 25


def threat_intel(domain: str, ips: list[str], api_get=net.api_get) -> CollectorResult:
    result = CollectorResult()
    otx_key = os.environ.get("PLATFORM_OTX_API_KEY", "").strip()
    abuse_key = os.environ.get("PLATFORM_ABUSEIPDB_API_KEY", "").strip()
    intel: dict = {"otx": {}, "abuseipdb": {}}
    if not otx_key and not abuse_key:
        result.notes.append("Threat-intel checks skipped (set PLATFORM_OTX_API_KEY and/or PLATFORM_ABUSEIPDB_API_KEY).")
        return result

    if otx_key:
        headers = {"X-OTX-API-KEY": otx_key}
        indicators = [("domain", domain)] + [("IPv6" if ":" in ip else "IPv4", ip) for ip in ips[:6]]
        for section, value in indicators:
            try:
                response = api_get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value)}/general",
                                   headers=headers, timeout=15)
            except Exception:
                continue
            if response.status_code != 200:
                continue
            pulses = (response.json().get("pulse_info") or {})
            count = int(pulses.get("count") or 0)
            names = [p.get("name", "") for p in (pulses.get("pulses") or [])[:5]]
            intel["otx"][value] = {"pulses": count, "names": names}
            if count:
                result.direct.append(DirectFinding("threat_intel_listing", f"{value} in {count} OTX pulse(s)",
                                                   f"otx:{value}", "; ".join(n for n in names if n)[:300]))

    if abuse_key:
        for ip in ips[:6]:
            try:
                response = api_get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                                   headers={"Key": abuse_key, "Accept": "application/json"}, timeout=15)
            except Exception:
                continue
            if response.status_code != 200:
                continue
            data = response.json().get("data") or {}
            score = int(data.get("abuseConfidenceScore") or 0)
            intel["abuseipdb"][ip] = {"score": score, "reports": data.get("totalReports"), "usage": data.get("usageType")}
            if score >= ABUSE_SCORE_THRESHOLD:
                result.direct.append(DirectFinding("ip_abuse_reported", f"{ip} abuse score {score}", f"abuseipdb:{ip}",
                                                   f"{data.get('totalReports')} reports in 90 days; confidence {score}%"))
    result.intel["threat_intel"] = intel
    return result


def _source_for(rule_id: str) -> SourceType:
    return {
        "search_indexed_sensitive_file": SourceType.SEARCH_RESULT,
        "search_indexed_directory_listing": SourceType.SEARCH_RESULT,
        "search_external_mention": SourceType.SEARCH_RESULT,
        "handle_reused_on_platform": SourceType.SOCIAL_PROFILE,
        "darkweb_mention": SourceType.LEAK_INDEX,
        "leak_index_exposure": SourceType.LEAK_INDEX,
        "threat_intel_listing": SourceType.THREAT_INTEL,
        "ip_abuse_reported": SourceType.THREAT_INTEL,
    }[rule_id]


__all__ = ["search_dorks", "username_presence", "leak_index", "ip_enrichment", "threat_intel", "RawFinding"]

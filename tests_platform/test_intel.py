"""Extended collectors (osint/intel.py): search engines, cross-platform
usernames, paste/leak/darknet index, ASN/GeoIP enrichment, threat intel.
All network calls are faked; no request leaves the test."""

from __future__ import annotations

import json

import httpx
import pytest

from test_monitoring import FakeResponse

KEYS = ("PLATFORM_BRAVE_SEARCH_API_KEY", "PLATFORM_SEARXNG_URL", "PLATFORM_INTELX_API_KEY", "PLATFORM_INTELX_API_URL",
        "PLATFORM_IPINFO_TOKEN", "PLATFORM_OTX_API_KEY", "PLATFORM_ABUSEIPDB_API_KEY")


@pytest.fixture(autouse=True)
def _no_keys(monkeypatch):
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)


# ------------------------------------------------------------------ search engines

def test_search_without_provider_explains_how_to_enable():
    from opsec_platform.app.osint import intel

    result = intel.search_dorks("domain", "example.com", ["example.com"])
    assert not result.direct and any("PLATFORM_BRAVE_SEARCH_API_KEY" in n for n in result.notes)


def test_brave_dorks_flag_indexed_files_listings_and_external_mentions(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_BRAVE_SEARCH_API_KEY", "bk")
    queries = []

    def api_get(url, params=None, headers=None, timeout=None):
        assert url == "https://api.search.brave.com/res/v1/web/search" and headers["X-Subscription-Token"] == "bk"
        q = params["q"]
        queries.append(q)
        if "ext:env" in q:
            results = [{"url": "https://www.example.com/.env", "title": "env", "description": "AWS_KEY=AKIAIOSFODNN7EXAMPLQ"},
                       {"url": "https://other.org/x.sql", "title": "x", "description": ""}]
        elif "index of" in q:
            results = [{"url": "https://example.com/uploads/", "title": "Index of /uploads", "description": ""}]
        elif q.startswith('"@example.com"'):
            results = [{"url": "https://forum.test/thread", "title": "contact admin@example.com", "description": "admin@example.com"}]
        else:
            results = []
        return FakeResponse(json_data={"web": {"results": results}})

    result = intel.search_dorks("domain", "example.com", ["example.com"], api_get=api_get)
    rules = sorted((d.rule_id, d.matched_text) for d in result.direct)
    assert ("search_indexed_sensitive_file", "https://www.example.com/.env") in rules
    assert ("search_indexed_directory_listing", "https://example.com/uploads/") in rules
    assert ("search_external_mention", "example.com on forum.test") in rules
    # A third-party .sql file is not "your site": no direct finding for it.
    assert not any("other.org" in m for _, m in rules)
    # Snippets go through the normal detection rules (the AWS key in the snippet).
    assert any("AKIAIOSFODNN7EXAMPLQ" in r.raw_text for r in result.raw)
    assert all(r.source_type.value == "search_result" for r in result.raw)
    assert len(queries) == 4 and result.intel["search"]["provider"] == "brave"


def test_searxng_goes_through_the_ssrf_guarded_client(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_SEARXNG_URL", "https://searx.example.org")
    calls = []

    def request(method, url, timeout=None, **kw):
        calls.append(url)
        return FakeResponse(json_data={"results": [{"url": "https://paste.test/a", "title": "me@example.com dump", "content": ""}]})

    result = intel.search_dorks("email", "me@example.com", [], request=request)
    assert calls and calls[0].startswith("https://searx.example.org/search?") and "format=json" in calls[0]
    assert [d.rule_id for d in result.direct] == ["search_external_mention"]


# ------------------------------------------------------------------ usernames

def test_username_presence_uses_platform_apis_and_reports_unknowns():
    from opsec_platform.app.osint import intel

    def api_get(url, params=None, headers=None, timeout=None):
        if "gitlab.com" in url:
            return FakeResponse(json_data=[{"id": 1, "username": "keshav"}])
        if "hacker-news" in url:
            return FakeResponse(json_data=None, body=b"null")
        if "reddit.com" in url:
            return FakeResponse(status=429)
        if "keybase.io" in url:
            return FakeResponse(json_data={"them": [None]})
        if "pypi.org" in url:
            return FakeResponse(status=200)
        return FakeResponse(status=404)

    result = intel.username_presence("keshav", api_get=api_get)
    found = {p["platform"] for p in result.intel["platforms"]["found"]}
    assert found == {"GitLab", "PyPI"}
    assert {d.rule_id for d in result.direct} == {"handle_reused_on_platform"}
    assert "Reddit" in result.intel["platforms"]["unknown"]


def test_username_with_odd_characters_is_not_sent_anywhere():
    from opsec_platform.app.osint import intel

    def api_get(*a, **k):
        raise AssertionError("no request expected")

    assert intel.username_presence("../admin", api_get=api_get).notes


# ------------------------------------------------------------------ Intelligence X

def _intelx_client(records, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["x-key"] == "ik" and request.url.host == "free.intelx.io"
        if request.url.path == "/intelligent/search":
            assert json.loads(request.content)["term"] == "me@example.com"
            return httpx.Response(200, json={"id": "sid-1", "status": 0})
        if request.url.path == "/intelligent/search/result":
            return httpx.Response(200, json={"records": records, "status": 1})
        return httpx.Response(200, json={})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_leak_index_maps_buckets_and_never_downloads_contents(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_INTELX_API_KEY", "ik")
    records = [
        {"systemid": "a", "bucket": "pastes", "name": "Pastebin abc", "date": "2026-01-02T00:00:00Z"},
        {"systemid": "b", "bucket": "darknet.tor", "name": "forum post", "date": "2025-07-01"},
        {"systemid": "c", "bucket": "leaks.public.general", "name": "combo.txt", "date": "2024-03-03"},
        {"systemid": "d", "bucket": "web.public.de", "name": "irrelevant"},
    ]
    seen = []
    result = intel.leak_index("me@example.com", client=_intelx_client(records, seen), poll_seconds=0)
    assert sorted(d.rule_id for d in result.direct) == ["darkweb_mention", "leak_index_exposure", "paste_exposure"]
    assert result.intel["leak_index"]["buckets"] == {"pastes": 1, "darknet.tor": 1, "leaks.public.general": 1}
    assert not any("/file/" in r.url.path for r in seen)  # metadata only


def test_leak_index_refuses_unknown_api_hosts(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_INTELX_API_KEY", "ik")
    monkeypatch.setenv("PLATFORM_INTELX_API_URL", "https://evil.example")
    assert any("must be" in n for n in intel.leak_index("x@example.com").notes)


# ------------------------------------------------------------------ ASN / GeoIP

def test_ip_enrichment_adds_asn_and_geo(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_IPINFO_TOKEN", "tok")
    dns = {("34.216.184.93.origin.asn.cymru.com", "TXT"): ["15133 | 93.184.216.0/24 | US | arin | 2008-06-02"],
           ("AS15133.asn.cymru.com", "TXT"): ["15133 | US | arin | 2007-03-19 | EDGECAST, US"]}

    def api_get(url, params=None, headers=None, timeout=None):
        assert url == "https://ipinfo.io/93.184.216.34/json" and params == {"token": "tok"}
        return FakeResponse(json_data={"city": "Los Angeles", "country": "US", "org": "AS15133 Edgecast"})

    ips = [{"ip": "93.184.216.34"}]
    intel.ip_enrichment(ips, lambda n, t: dns.get((n, t), []), api_get=api_get)
    assert ips[0]["asn"] == "AS15133" and ips[0]["asn_name"] == "EDGECAST, US"
    assert ips[0]["prefix"] == "93.184.216.0/24" and ips[0]["geo"]["city"] == "Los Angeles"


def test_cymru_name_for_ipv6():
    from opsec_platform.app.osint.intel import _cymru_origin_name

    assert _cymru_origin_name("2001:db8::1").endswith(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")


# ------------------------------------------------------------------ threat intel

def test_threat_intel_flags_otx_pulses_and_abuse_scores(monkeypatch):
    from opsec_platform.app.osint import intel

    monkeypatch.setenv("PLATFORM_OTX_API_KEY", "ok")
    monkeypatch.setenv("PLATFORM_ABUSEIPDB_API_KEY", "ak")

    def api_get(url, params=None, headers=None, timeout=None):
        if "otx.alienvault.com" in url:
            assert headers["X-OTX-API-KEY"] == "ok"
            if "/domain/example.com/" in url:
                return FakeResponse(json_data={"pulse_info": {"count": 2, "pulses": [{"name": "Phishing kit"}, {"name": "C2"}]}})
            return FakeResponse(json_data={"pulse_info": {"count": 0, "pulses": []}})
        if "abuseipdb" in url:
            assert headers["Key"] == "ak"
            score = 80 if params["ipAddress"] == "1.2.3.4" else 0
            return FakeResponse(json_data={"data": {"abuseConfidenceScore": score, "totalReports": 12}})
        return FakeResponse(status=404)

    result = intel.threat_intel("example.com", ["1.2.3.4", "5.6.7.8"], api_get=api_get)
    rules = sorted((d.rule_id, d.matched_text) for d in result.direct)
    assert rules == [("ip_abuse_reported", "1.2.3.4 abuse score 80"), ("threat_intel_listing", "example.com in 2 OTX pulse(s)")]
    assert result.intel["threat_intel"]["abuseipdb"]["5.6.7.8"]["score"] == 0


def test_threat_intel_without_keys_is_a_note():
    from opsec_platform.app.osint import intel

    assert any("PLATFORM_OTX_API_KEY" in n for n in intel.threat_intel("example.com", []).notes)


def test_every_new_direct_rule_is_registered_with_source_and_remediation():
    from opsec_platform.app.osint import collectors, service

    new = ["search_indexed_sensitive_file", "search_indexed_directory_listing", "search_external_mention",
           "handle_reused_on_platform", "darkweb_mention", "leak_index_exposure", "threat_intel_listing", "ip_abuse_reported"]
    for rule in new:
        assert rule in collectors.DIRECT_RULES and rule in service.DIRECT_SOURCE and rule in collectors.DIRECT_REMEDIATION

"""
Monitoring modules: targets + ownership verification, collectors (with
fake network), SSRF guard, triage, global search, reports, identity graph,
integrations/alerts and the scheduler.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")

AWS = "AKIAIOSFODNN7EXAMPLQ"


@pytest.fixture
def client(tmp_path, monkeypatch):
    import opsec_platform.app.dependencies as deps

    deps._engine = None
    deps._SessionLocal = None
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path / 'm.db'}")
    for key in ("PLATFORM_GITHUB_TOKEN", "PLATFORM_HIBP_API_KEY", "PLATFORM_SHODAN_API_KEY", "PLATFORM_LLM_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    from opsec_platform.app.main import create_app

    c = TestClient(create_app())
    c.post("/auth/register", json={"email": "owner@example.com", "password": "testpass123", "org_name": "Acme"})
    c.post("/auth/login", json={"email": "owner@example.com", "password": "testpass123"})
    return c


def wait():
    from opsec_platform.app import scan_service

    scan_service.wait_for_idle(60)


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, url="", json_data=None):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode()
        self.headers = {"content-type": "text/html", **(headers or {})}
        self.url = url
        self.truncated = False
        self._json = json_data

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")

    def json(self):
        return self._json if self._json is not None else json.loads(self.text)


# ---------------------------------------------------------------- targets / verification

def test_domain_target_requires_verification(client, monkeypatch):
    from opsec_platform.app.osint import verification

    r = client.post("/targets", json={"kind": "domain", "value": "https://www.Example.com/", "schedule": "daily"})
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["value"] == "example.com" and t["verified"] is False
    record = t["verification"]["methods"][0]["record"]
    assert record.startswith("opsec-scanner-verify=")
    assert client.post(f"/targets/{t['id']}/scan").status_code == 403

    monkeypatch.setattr(verification, "check_dns_txt", lambda d, tok: False)
    monkeypatch.setattr(verification, "check_well_known", lambda d, tok: False)
    assert client.post(f"/targets/{t['id']}/verify", json={}).status_code == 400

    monkeypatch.setattr(verification, "check_dns_txt", lambda d, tok: d == "example.com" and record.endswith(tok))
    v = client.post(f"/targets/{t['id']}/verify", json={}).json()
    assert v["verified"] and v["verification_method"] == "dns_txt" and v["next_run_at"]
    assert v["verification"] is None
    assert client.post("/targets", json={"kind": "domain", "value": "example.com"}).status_code == 409


def test_email_and_url_auto_verification(client, monkeypatch):
    own = client.post("/targets", json={"kind": "email", "value": "Owner@Example.com"}).json()
    assert own["verified"] and own["verification_method"] == "account_email"
    other = client.post("/targets", json={"kind": "email", "value": "someone@else.com"}).json()
    assert not other["verified"]
    assert client.post(f"/targets/{other['id']}/verify", json={}).status_code == 400

    url = client.post("/targets", json={"kind": "url", "value": "https://blog.example.com/post"}).json()
    assert not url["verified"]
    from opsec_platform.app.osint import verification
    monkeypatch.setattr(verification, "check_dns_txt", lambda d, tok: True)
    dom = client.post("/targets", json={"kind": "domain", "value": "example.com"}).json()
    client.post(f"/targets/{dom['id']}/verify", json={})
    assert client.post(f"/targets/{url['id']}/verify", json={}).json()["verified"] is True


@pytest.mark.parametrize("kind,value", [("domain", "localhost"), ("domain", "not a domain"), ("url", "ftp://x.com"),
                                        ("url", "https://u:p@x.com/"), ("github_handle", "-bad-"), ("email", "nope")])
def test_target_validation(client, kind, value):
    assert client.post("/targets", json={"kind": kind, "value": value}).status_code == 422


def test_targets_are_private(client):
    t = client.post("/targets", json={"kind": "email", "value": "owner@example.com"}).json()
    client.post("/auth/logout")
    client.post("/auth/register", json={"email": "x@example.com", "password": "testpass123", "org_name": "Other"})
    client.post("/auth/login", json={"email": "x@example.com", "password": "testpass123"})
    assert client.post(f"/targets/{t['id']}/scan").status_code == 404
    assert client.delete(f"/targets/{t['id']}").status_code == 404
    assert client.get("/targets").json() == []


# ---------------------------------------------------------------- monitoring scan end to end

def _fake_collect(target, domains):
    from opsec_platform.app.osint.collectors import CollectorResult, DirectFinding
    from opsec_scanner.models import RawFinding, SourceType

    r = CollectorResult()
    r.raw.append(RawFinding(source_type=SourceType.WEB_CONTENT, raw_text=f"const key = '{AWS}';", origin="https://example.com/app.js", context="line 3"))
    r.raw.append(RawFinding(source_type=SourceType.WEB_CONTENT, raw_text="card 4111 1111 1111 1111", origin="https://example.com/x", context="line 9"))
    r.direct.append(DirectFinding("missing_dmarc", "example.com DMARC", "dns:_dmarc.example.com", "No _dmarc TXT record"))
    r.direct.append(DirectFinding("exposed_git_directory", "https://example.com/.git/HEAD", "https://example.com/.git/HEAD", "HTTP 200"))
    r.intel["dns"] = {"A": ["93.184.216.34"]}
    r.intel["subdomains"] = ["dev.example.com"]
    r.notes.append("Shodan port data skipped (set PLATFORM_SHODAN_API_KEY to enable).")
    return r


def _verified_domain(client, monkeypatch):
    from opsec_platform.app.osint import service, verification

    monkeypatch.setattr(verification, "check_dns_txt", lambda d, tok: True)
    monkeypatch.setattr(service, "collect", _fake_collect)
    t = client.post("/targets", json={"kind": "domain", "value": "example.com"}).json()
    return client.post(f"/targets/{t['id']}/verify", json={}).json()


def test_monitor_scan_stores_findings_with_mitre_and_intel(client, monkeypatch):
    t = _verified_domain(client, monkeypatch)
    r = client.post(f"/targets/{t['id']}/scan")
    assert r.status_code == 202 and r.json()["source"] == "monitor"
    wait()
    scan = client.get(f"/scans/{r.json()['id']}").json()
    assert scan["status"] == "completed", scan
    assert scan["stats"]["intel"]["subdomains"] == ["dev.example.com"]
    items = client.get(f"/scans/{scan['id']}/findings").json()["items"]
    by_rule = {i["rule_id"]: i for i in items}
    assert {"aws_access_key", "credit_card_number", "missing_dmarc", "exposed_git_directory"} <= set(by_rule)
    assert by_rule["aws_access_key"]["mitre"] == "T1552.001"
    assert by_rule["exposed_git_directory"]["mitre"] == "T1213"
    assert all(i["exposure_level"] == "public_reachable" for i in items)
    assert AWS not in json.dumps(items) and "4111 1111 1111 1111" not in json.dumps(items)
    intel = client.get("/intel/domains").json()
    assert intel[0]["domain"] == "example.com" and intel[0]["intel"]["dns"]["A"] == ["93.184.216.34"]


# ---------------------------------------------------------------- triage, search, reports

def test_triage_status_persists_across_scans_and_search(client, monkeypatch):
    t = _verified_domain(client, monkeypatch)
    first = client.post(f"/targets/{t['id']}/scan").json()
    wait()
    items = client.get(f"/scans/{first['id']}/findings").json()["items"]
    dmarc = next(i for i in items if i["rule_id"] == "missing_dmarc")
    r = client.patch(f"/findings/{dmarc['id']}/status", json={"status": "suppressed", "note": "accepted risk"})
    assert r.status_code == 200 and r.json()["status"] == "suppressed"
    assert client.patch(f"/findings/{dmarc['id']}/status", json={"status": "bogus"}).status_code == 422

    second = client.post(f"/targets/{t['id']}/scan").json()
    wait()
    again = client.get(f"/scans/{second['id']}/findings?status=suppressed").json()["items"]
    assert [i["rule_id"] for i in again] == ["missing_dmarc"]

    found = client.get("/findings?mitre=T1552.001").json()
    assert found["total"] == 1 and found["items"][0]["rule_id"] == "aws_access_key"
    assert found["items"][0]["target_label"] == "domain:example.com"
    assert client.get("/findings?status=open&q=.git").json()["total"] == 1

    summary = client.get("/reports/summary").json()
    assert summary["open_findings"] == 3 and summary["triage"]["suppressed"] == 1
    assert 0 < summary["exposure_index"] <= 10
    assert any(r["category"] == "credentials" for r in summary["recommendations"])
    assert summary["narrative"] is None

    pdf = client.get("/reports/summary.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    txt = client.get("/reports/summary.txt").text
    assert "Exposure index" in txt and AWS not in txt
    assert client.get(f"/scans/{second['id']}/export?format=pdf").content.startswith(b"%PDF")
    assert "missing_dmarc" in client.get(f"/scans/{second['id']}/export?format=txt").text


def test_identity_graph_and_rule_catalog(client, monkeypatch):
    t = _verified_domain(client, monkeypatch)
    client.put("/profile/identity", json={"name": "Owner", "emails": ["owner@example.com"], "domains": ["example.com"]})
    client.post(f"/targets/{t['id']}/scan")
    wait()
    graph = client.get("/identity/graph").json()
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"person", "email", "domain", "target", "scan", "finding"} <= kinds
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in graph["edges"])
    rules = client.get("/rules").json()
    assert any(r["id"] == "credit_card_number" and r["mitre"] for r in rules)
    assert all(r.get("mitre") for r in rules)


# ---------------------------------------------------------------- integrations / alerts

def test_integration_config_is_validated_encrypted_and_hidden(client):
    bad = client.post("/integrations", json={"kind": "slack", "name": "x", "config": {"webhook_url": "https://evil.example/hook"}})
    assert bad.status_code == 422
    hook = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnop"
    r = client.post("/integrations", json={"kind": "slack", "name": "Team", "config": {"webhook_url": hook}})
    assert r.status_code == 201 and "config" not in r.json() and hook not in json.dumps(r.json())
    from opsec_platform.app import dependencies
    from opsec_platform.app.models import Integration
    db = dependencies._SessionLocal()
    try:
        assert hook not in db.query(Integration).first().config_encrypted
    finally:
        db.close()
    assert client.post("/integrations", json={"kind": "webhook", "name": "siem", "config": {"url": "http://x.com"}}).status_code == 422
    assert client.post("/integrations", json={"kind": "email", "name": "mail", "config": {}}).status_code == 422


def test_alerts_send_only_new_findings_above_threshold(client, monkeypatch):
    from opsec_platform.app import alerts

    sent = []
    monkeypatch.setattr(alerts, "send", lambda kind, config, alert, email, **kw: sent.append((kind, config, alert)))
    client.post("/integrations", json={"kind": "discord", "name": "d", "min_severity": "HIGH",
                                       "config": {"webhook_url": "https://discord.com/api/webhooks/1/abcdefghijklmnopqrstuvwxyzABCDEF"}})
    t = _verified_domain(client, monkeypatch)
    client.post(f"/targets/{t['id']}/scan")
    wait()
    wait()
    assert len(sent) == 1
    kind, config, alert = sent[0]
    assert kind == "discord" and config["webhook_url"].startswith("https://discord.com/")
    rules = {f["rule_id"] for f in alert["payload"]["findings"]}
    assert "missing_dmarc" not in rules and "exposed_git_directory" in rules
    assert AWS not in json.dumps(alert)
    client.post(f"/targets/{t['id']}/scan")
    wait()
    wait()
    assert len(sent) == 1  # nothing new the second time


def test_webhook_payload_is_signed():
    from opsec_platform.app import alerts

    captured = {}

    def post(method, url, data=None, headers=None, **kw):
        captured.update(url=url, data=data, headers=headers)
        return type("R", (), {"status_code": 204})()

    alert = {"title": "t", "summary": "", "lines": [], "link": "", "payload": {"event": "x"}}
    alerts.send("webhook", {"url": "https://siem.example/in", "secret": "s3cret"}, alert, "", post=post)
    import hashlib, hmac
    expected = "sha256=" + hmac.new(b"s3cret", captured["data"], hashlib.sha256).hexdigest()
    assert captured["headers"]["X-OPSEC-Signature"] == expected


# ---------------------------------------------------------------- scheduler

def test_scheduler_claims_due_targets_once(client, monkeypatch):
    from opsec_platform.app import dependencies
    from opsec_platform.app.models import MonitoredTarget
    from opsec_platform.app.osint import scheduler

    t = _verified_domain(client, monkeypatch)
    db = dependencies._SessionLocal()
    try:
        row = db.get(MonitoredTarget, t["id"])
        row.schedule = "weekly"
        row.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    calls = []
    first = scheduler.run_due(submit=lambda *a: calls.append(a))
    second = scheduler.run_due(submit=lambda *a: calls.append(a))
    assert len(first) == 1 and second == [] and len(calls) == 1


# ---------------------------------------------------------------- collectors with fake network

def test_crawler_stays_in_scope_and_respects_robots():
    from opsec_platform.app.osint import collectors

    pages = {
        "https://example.com/robots.txt": FakeResponse(body="User-agent: *\nDisallow: /private", headers={"content-type": "text/plain"}),
        "https://example.com/": FakeResponse(body=f'<html><a href="/a">a</a><a href="https://evil.com/x">x</a>'
                                                  f'<a href="/private/s">p</a><script>var k="{AWS}"</script></html>'),
        "https://example.com/a": FakeResponse(body="<html>contact +91 98765 43210</html>"),
    }
    fetched = []

    def fetch(method, url, **kw):
        fetched.append(url)
        resp = pages.get(url, FakeResponse(status=404))
        resp.url = url
        return resp

    result = collectors.crawl_site(["https://example.com/"], ["example.com"], fetch=fetch)
    assert "https://evil.com/x" not in fetched and "https://example.com/private/s" not in fetched
    texts = " ".join(r.raw_text for r in result.raw)
    assert AWS in texts and "+91 98765 43210" in texts
    assert result.intel["pages_crawled"] == 2


def test_exposure_checks_detect_git_and_env():
    from opsec_platform.app.osint import collectors

    def fetch(method, url, **kw):
        if url.endswith("/.git/HEAD"):
            return FakeResponse(body="ref: refs/heads/main\n", headers={"content-type": "text/plain"})
        if url.endswith("/.env"):
            return FakeResponse(body=f"AWS_KEY={AWS}\nDEBUG=1\n", headers={"content-type": "text/plain"})
        if url.endswith("/"):
            return FakeResponse(body="<html></html>", headers={"strict-transport-security": "max-age=1"})
        return FakeResponse(status=404)

    result = collectors.exposure_checks("example.com", fetch=fetch)
    rules = {d.rule_id for d in result.direct}
    assert {"exposed_git_directory", "exposed_env_file", "missing_security_headers"} <= rules
    assert any(AWS in r.raw_text for r in result.raw)


def test_public_records_flags_email_security_subdomains_and_whois():
    from opsec_platform.app.osint import collectors

    dns = {("example.com", "MX"): ["10 mail.example.com"], ("example.com", "TXT"): ["v=spf1 include:x +all"],
           ("example.com", "A"): ["93.184.216.34"]}

    def lookup(name, rtype):
        return dns.get((name, rtype), [])

    def api_get(url, params=None, headers=None, timeout=None):
        if "crt.sh" in url:
            return FakeResponse(json_data=[{"name_value": "www.example.com\nstaging.example.com"}, {"name_value": "*.jenkins.example.com"}])
        if "rdap.org/domain" in url:
            return FakeResponse(json_data={"entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Owner Person"], ["email", {}, "text", "owner@gmail.com"]]]},
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc"]]]}],
                "events": [{"eventAction": "expiration", "eventDate": "2030-01-01"}]})
        if "rdap.org/ip" in url:
            return FakeResponse(json_data={"name": "EDGECAST", "country": "US", "startAddress": "93.184.216.0", "endAddress": "93.184.216.255"})
        return FakeResponse(status=404)

    result = collectors.public_records("example.com", dns_lookup=lookup, api_get=api_get)
    rules = sorted(d.rule_id for d in result.direct)
    assert "permissive_spf" in rules and "missing_dmarc" in rules and "whois_registrant_exposed" in rules
    assert [d.matched_text for d in result.direct if d.rule_id == "sensitive_subdomain"] == ["jenkins.example.com", "staging.example.com"]
    assert result.intel["rdap"]["registrar"] == "Registrar Inc"
    assert result.intel["ips"][0]["network"] == "EDGECAST"
    assert any("Shodan" in n for n in result.notes)


def test_optional_sources_report_missing_keys():
    from opsec_platform.app.osint import collectors

    assert any("PLATFORM_GITHUB_TOKEN" in n for n in collectors.github_code_search("example.com").notes)
    assert any("PLATFORM_HIBP_API_KEY" in n for n in collectors.breach_check("a@b.com").notes)


def test_breach_check_with_key(monkeypatch):
    from opsec_platform.app.osint import collectors

    monkeypatch.setenv("PLATFORM_HIBP_API_KEY", "k")

    def api_get(url, params=None, headers=None, timeout=None):
        assert headers["hibp-api-key"] == "k"
        if "breachedaccount" in url:
            return FakeResponse(json_data=[{"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Emails", "Passwords"]}])
        return FakeResponse(status=404)

    result = collectors.breach_check("owner@example.com", api_get=api_get)
    assert [d.rule_id for d in result.direct] == ["breach_exposure"]
    assert result.intel["breaches"][0]["name"] == "Adobe"


# ---------------------------------------------------------------- SSRF guard

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"])
def test_private_addresses_are_refused(ip):
    from opsec_platform.app.osint import net

    assert not net.is_public_ip(ip)
    with pytest.raises(net.UnsafeTarget):
        net.safe_request("GET", "https://looks-fine.example/", resolver=lambda h, p: (_ for _ in ()).throw(net.UnsafeTarget("x"))
                         if not net.is_public_ip(ip) else [ip])


def test_resolve_public_rejects_any_private_answer(monkeypatch):
    import socket
    from opsec_platform.app.osint import net

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("93.184.216.34", 443)), (0, 0, 0, "", ("10.0.0.5", 443))])
    with pytest.raises(net.UnsafeTarget):
        net.resolve_public("mixed.example", 443)


@pytest.mark.parametrize("url", ["ftp://x.com/", "https://u:p@x.com/", "https://x.com:8443/", "file:///etc/passwd"])
def test_validate_url_rejects(url):
    from opsec_platform.app.osint import net

    with pytest.raises(net.UnsafeTarget):
        net.validate_url(url)


def test_gist_verification_falls_back_to_listing_page_when_api_is_rate_limited():
    from opsec_platform.app.osint import verification

    def api_get(url, params=None, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(status=403, json_data={"message": "API rate limit exceeded"})
        assert url == "https://gist.github.com/Keshav-gehlot"
        return FakeResponse(body="<html>opsec-scanner-verify TOKEN123</html>")

    assert verification.check_github_gist("Keshav-gehlot", "TOKEN123", api_get=api_get)
    assert not verification.check_github_gist("Keshav-gehlot", "OTHER", api_get=api_get)


def test_gist_verification_uses_api_owner_check():
    from opsec_platform.app.osint import verification

    def api_get(url, params=None, headers=None, timeout=None):
        if "api.github.com" in url:
            return FakeResponse(json_data=[{"owner": {"login": "someone-else"}, "description": "TOKEN123"}])
        return FakeResponse(status=404)

    assert not verification.check_github_gist("Keshav-gehlot", "TOKEN123", api_get=api_get)


def test_handle_collector_reports_rate_limit():
    from opsec_platform.app.osint import collectors

    result = collectors.github_handle("x", api_get=lambda *a, **k: FakeResponse(status=403, json_data={}))
    assert any("PLATFORM_GITHUB_TOKEN" in n for n in result.notes)

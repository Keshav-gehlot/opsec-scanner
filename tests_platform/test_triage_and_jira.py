"""Optional LLM triage of findings, and the Jira integration."""

import base64
import json
import os

import pytest

os.environ.setdefault("PLATFORM_JWT_SECRET", "test-secret-do-not-use-in-prod")
os.environ.setdefault("PLATFORM_COOKIE_SECURE", "false")

from test_scans import AWS_KEY, client, export_payload, finding, signup, wait  # noqa: F401,E402


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


def test_triage_disabled_by_default(monkeypatch):
    from opsec_platform.app import triage

    monkeypatch.delenv("PLATFORM_LLM_TRIAGE", raising=False)
    monkeypatch.setenv("PLATFORM_LLM_API_KEY", "k")
    monkeypatch.setenv("PLATFORM_LLM_MODEL", "m")
    assert not triage.enabled()
    monkeypatch.setenv("PLATFORM_LLM_TRIAGE", "true")
    assert triage.enabled()


def test_triage_sends_only_redacted_fields_and_stores_verdicts(client, monkeypatch):  # noqa: F811
    from opsec_platform.app import triage

    monkeypatch.setenv("PLATFORM_LLM_TRIAGE", "false")  # don't auto-run; call it directly below
    signup(client)
    payload = export_payload([finding(), finding(rule="internal_ip_range", text="10.20.30.40", label="MEDIUM", score=5.0,
                                              context="tests/fixtures/sample.env, line 2")])
    scan = client.post("/scans/import?label=repo", json=payload).json()
    items = client.get(f"/scans/{scan['id']}/findings").json()["items"]
    ids = {i["rule_id"]: i["id"] for i in items}

    sent = {}

    def post(url, headers, json, timeout):  # noqa: A002
        sent["url"], sent["body"] = url, json
        reply = [{"id": ids["aws_access_key"], "verdict": "likely_real", "reason": "Real-looking key in app code"},
                 {"id": ids["internal_ip_range"], "verdict": "likely_test", "reason": "Fixture file"},
                 {"id": 999999, "verdict": "likely_real", "reason": "not in this scan"}]
        return Resp(200, {"content": [{"type": "text", "text": "Here you go:\n" + __import__("json").dumps(reply)}]})

    monkeypatch.setenv("PLATFORM_LLM_API_KEY", "test-key")
    monkeypatch.setenv("PLATFORM_LLM_MODEL", "test-model")
    assert triage.triage_scan(scan["id"], post=post) == 2
    prompt = sent["body"]["messages"][0]["content"]
    assert AWS_KEY not in prompt and "10.20.30.40" not in prompt and "Should Not Be Stored" not in prompt
    assert sent["url"] == triage.API_URL

    by_rule = {i["rule_id"]: i for i in client.get(f"/scans/{scan['id']}/findings").json()["items"]}
    assert by_rule["aws_access_key"]["ai_verdict"] == "likely_real"
    assert by_rule["internal_ip_range"]["ai_verdict"] == "likely_test"
    assert by_rule["internal_ip_range"]["ai_reason"] == "Fixture file"
    # Already-classified findings are not re-sent.
    assert triage.triage_scan(scan["id"], post=post) == 0


def test_triage_failures_are_silent():
    from opsec_platform.app import triage

    class Row:
        id, rule_id, category, source_type, preview, context = 1, "r", "c", "s", "p••", "x"

    assert triage.classify([Row()], post=lambda *a, **k: Resp(500, {})) == {}
    assert triage.classify([Row()], post=lambda *a, **k: Resp(200, {"content": [{"text": "not json"}]})) == {}
    bad = [{"id": 1, "verdict": "definitely", "reason": "x"}]
    assert triage.classify([Row()], post=lambda *a, **k: Resp(200, {"content": [{"text": json.dumps(bad)}]})) == {}

    def boom(*a, **k):
        raise RuntimeError("network down")

    assert triage.classify([Row()], post=boom) == {}


# ---------------------------------------------------------------- Jira

def test_jira_config_validation():
    from opsec_platform.app.alerts import IntegrationError, validate_config

    good = {"base_url": "https://acme.atlassian.net/", "email": "sec@acme.io", "api_token": "a" * 24, "project_key": "sec"}
    config, hint = validate_config("jira", good)
    assert config["base_url"] == "https://acme.atlassian.net" and config["project_key"] == "SEC"
    assert config["issue_type"] == "Task" and hint == "acme.atlassian.net · SEC"
    for bad in ({**good, "base_url": "https://evil.example.com"}, {**good, "base_url": "http://acme.atlassian.net"},
                {**good, "base_url": "https://acme.atlassian.net/rest/api"}, {**good, "email": "nope"},
                {**good, "api_token": "short"}, {**good, "project_key": "1x"}):
        with pytest.raises(IntegrationError):
            validate_config("jira", bad)


def test_jira_send_creates_issue_with_adf_body():
    from opsec_platform.app import alerts

    calls = []

    def post(method, url, json_body=None, headers=None, timeout=None, **kw):
        calls.append((method, url, json_body, headers))
        return Resp(201, {"key": "SEC-1"})

    config = {"base_url": "https://acme.atlassian.net", "email": "sec@acme.io", "api_token": "tok" * 8,
              "project_key": "SEC", "issue_type": "Bug"}
    alert = {"title": "OPSEC Scanner: 1 finding(s) on repo", "summary": "1 critical",
             "lines": ["[CRITICAL] aws_access_key AKIA•••• — repo"], "link": "https://x/dashboard#/scan/1", "payload": {}}
    alerts.send("jira", config, alert, "", post=post)
    method, url, body, headers = calls[0]
    assert method == "POST" and url == "https://acme.atlassian.net/rest/api/3/issue"
    assert base64.b64decode(headers["Authorization"].split()[1]).decode() == "sec@acme.io:" + "tok" * 8
    fields = body["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Bug"}
    assert fields["description"]["type"] == "doc" and "aws_access_key" in json.dumps(fields["description"])

    with pytest.raises(alerts.IntegrationError):
        alerts.send("jira", config, alert, "", post=lambda *a, **k: Resp(400, {}))


def test_jira_integration_via_api(client):  # noqa: F811
    signup(client)
    r = client.post("/integrations", json={"kind": "jira", "name": "Tickets", "config": {
        "base_url": "https://acme.atlassian.net", "email": "sec@acme.io", "api_token": "x" * 24, "project_key": "SEC"}})
    assert r.status_code in (200, 201), r.text
    assert "x" * 24 not in r.text

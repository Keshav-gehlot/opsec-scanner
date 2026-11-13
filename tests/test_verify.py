"""--verify-secrets, against a mock transport (no real credentials leave the test)."""

import httpx

from opsec_scanner.analysis.patterns import ScannedMatch
from opsec_scanner.analysis.verify import CHECKS, verify_findings, verifiable
from opsec_scanner.config import TargetProfile
from opsec_scanner.models import RawFinding, SourceType
from opsec_scanner.scoring.risk_engine import score_findings

LIVE = "ghp_" + "L" * 36
DEAD = "ghp_" + "D" * 36


def _scored(*pairs):
    matches = [
        ScannedMatch(finding=RawFinding(source_type=SourceType.GIT_PATCH, raw_text=v, origin="a.py"),
                     rule_id=rule, category="credentials", base_severity=9.5, matched_text=v)
        for rule, v in pairs
    ]
    return score_findings(matches, TargetProfile(name="T"))


def _client(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.github.com":
            token = request.headers["authorization"].split()[-1]
            return httpx.Response(200 if token == LIVE else 401, json={})
        if request.url.host == "slack.com":
            return httpx.Response(200, json={"ok": False, "error": "invalid_auth"})
        return httpx.Response(503)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_live_credential_escalates_to_critical_and_dead_one_is_marked():
    scored = _scored(("github_pat", LIVE), ("github_pat", DEAD), ("slack_token", "xoxb-1234567890-abcdef"))
    assert all(s.risk_label != "CRITICAL" for s in scored)  # unverified, no identity match
    seen = []
    counts = verify_findings(scored, client=_client(seen))
    assert counts == {"active": 1, "inactive": 2, "unknown": 0, "skipped": 0}
    by_value = {s.match.matched_text: s for s in scored}
    assert by_value[LIVE].risk_label == "CRITICAL" and by_value[LIVE].match.finding.metadata["verification"] == "active"
    assert by_value[DEAD].risk_label != "CRITICAL" and by_value[DEAD].match.finding.metadata["verification"] == "inactive"
    assert scored[0].match.matched_text == LIVE  # re-sorted
    # Every request went to the credential's own issuer, over HTTPS.
    assert {r.url.host for r in seen} == {"api.github.com", "slack.com"}
    assert all(r.url.scheme == "https" for r in seen)


def test_duplicates_checked_once_and_limit_respected():
    scored = _scored(("github_pat", LIVE), ("github_pat", LIVE), ("github_pat", DEAD))
    seen = []
    counts = verify_findings(scored, client=_client(seen), max_checks=1)
    assert len(seen) == 1 and counts["skipped"] == 1


def test_unverifiable_types_and_publishable_keys_are_skipped():
    assert not verifiable("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    assert not verifiable("stripe_key", "pk_live_" + "a" * 24)
    assert verifiable("stripe_key", "sk_live_" + "a" * 24)
    scored = _scored(("aws_access_key", "AKIAIOSFODNN7EXAMPLE"))
    seen = []
    assert verify_findings(scored, client=_client(seen))["active"] == 0 and not seen


def test_network_errors_are_unknown_not_inactive():
    def boom(request):
        raise httpx.ConnectError("down")
    scored = _scored(("github_pat", LIVE))
    counts = verify_findings(scored, client=httpx.Client(transport=httpx.MockTransport(boom)))
    assert counts["unknown"] == 1 and scored[0].risk_label != "CRITICAL"


def test_every_check_uses_https():
    assert all(c.url.startswith("https://") for c in CHECKS.values())

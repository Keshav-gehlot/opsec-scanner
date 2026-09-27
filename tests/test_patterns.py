import pytest

from opsec_scanner.analysis.patterns import scan_findings, load_rules, load_allowlist, Allowlist
from opsec_scanner.models import RawFinding, SourceType


def _finding(text, origin="test.txt"):
    return RawFinding(source_type=SourceType.GIT_PATCH, raw_text=text, origin=origin)


def test_aws_key_detected():
    findings = [_finding("aws_key=AKIAIOSFODNN7EXAMPLE")]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert any(m.rule_id == "aws_access_key" for m in matches)


def test_github_pat_detected():
    findings = [_finding("token: ghp_" + "a" * 36)]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert any(m.rule_id == "github_pat" for m in matches)


def test_low_entropy_placeholder_not_flagged_as_credential():
    # "password=hunter2" is exactly the placeholder case the entropy
    # gate exists to filter out of the generic key=value rule.
    findings = [_finding("password=hunter2")]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert not any(m.rule_id == "generic_api_key_assignment" for m in matches)


def test_underscore_prefixed_var_still_matches():
    # Regression test for the \b boundary bug: DB_PASSWORD=<random> must
    # still match despite the leading underscore. Value needs to be long
    # enough to clear the entropy gate (see calibration note in entropy.py).
    findings = [_finding("DB_PASSWORD=xK9mZ2pQ7wRaB3tL8vN4cF6hJ2kM9")]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert any(m.rule_id == "generic_api_key_assignment" for m in matches)


def test_allowlisted_pattern_suppressed():
    findings = [_finding("AKIAIOSFODNN7EXAMPLE")]
    allowlist = Allowlist(ignore_patterns=["AKIAIOSFODNN7EXAMPLE"])
    matches = scan_findings(findings, load_rules(), allowlist=allowlist)
    assert len(matches) == 0


def test_allowlisted_path_suppressed():
    findings = [_finding("aws_key=AKIAIOSFODNN7EXAMPLE", origin="/repo/node_modules/pkg/file.js")]
    allowlist = Allowlist(ignore_paths=["/node_modules/"])
    matches = scan_findings(findings, load_rules(), allowlist=allowlist)
    assert len(matches) == 0


def test_internal_ip_detected():
    findings = [_finding("connect to 10.0.5.23 for staging")]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert any(m.rule_id == "internal_ip_range" for m in matches)


def test_public_ip_not_flagged_as_internal():
    findings = [_finding("connect to 8.8.8.8 for DNS")]
    matches = scan_findings(findings, load_rules(), allowlist=Allowlist())
    assert not any(m.rule_id == "internal_ip_range" for m in matches)


def test_malformed_regex_in_custom_rule_is_skipped_not_fatal(tmp_path):
    # Regression test: one typo'd regex in a custom rules file previously
    # crashed the whole tool. A single bad rule should be skipped with a
    # warning, not take every other rule down with it.
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("""
rules:
  - id: good_rule
    category: credentials
    regex: 'AKIA[0-9A-Z]{16}'
    base_severity: 9.0
    description: "valid"
  - id: bad_rule
    category: credentials
    regex: '[unclosed_bracket'
    base_severity: 8.0
    description: "invalid regex"
""")
    rules = load_rules(rules_file)
    assert len(rules) == 1
    assert rules[0].id == "good_rule"


def test_corrupt_rules_yaml_raises_rather_than_silently_scanning_with_zero_rules(tmp_path):
    # Unlike the allowlist (which degrades gracefully since it's just a
    # false-positive filter), the rule set is core detection — silently
    # falling back to zero rules here would mean a scan reports a false
    # "all clean" result instead of failing. Must exit, not swallow.
    rules_file = tmp_path / "corrupt_rules.yaml"
    rules_file.write_text("rules: [[[not valid")

    with pytest.raises(SystemExit):
        load_rules(rules_file)


def test_corrupt_allowlist_degrades_gracefully_scan_still_runs(tmp_path):
    # Unlike the rules file, a corrupt allowlist should NOT stop the
    # scan — it's a false-positive suppression aid, not core detection,
    # so degrading to "no allowlist" and continuing is the safer default.
    allowlist_file = tmp_path / "corrupt_allowlist.yaml"
    allowlist_file.write_text("ignore_patterns: [[[")

    allowlist = load_allowlist(allowlist_file)
    assert allowlist.ignore_patterns == []
    assert allowlist.ignore_paths == []

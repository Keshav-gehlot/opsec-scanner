"""New detection rules, checksum validators and MITRE mapping."""

import pytest

from opsec_scanner.analysis.patterns import aadhaar_valid, iban_valid, load_rules, luhn_valid, scan_findings, ssn_valid
from opsec_scanner.models import RawFinding, SourceType


def rules_hit(text):
    finding = RawFinding(source_type=SourceType.MEDIA_DOC, raw_text=text, origin="doc.txt")
    return {m.rule_id for m in scan_findings([finding], load_rules())}


def test_validators():
    assert luhn_valid("4111 1111 1111 1111") and not luhn_valid("4111 1111 1111 1112") and not luhn_valid("0000 0000 0000 0000")
    assert iban_valid("GB82 WEST 1234 5698 7654 32") and not iban_valid("GB82 WEST 1234 5698 7654 33")
    assert ssn_valid("123-45-6789") and not ssn_valid("000-12-3456") and not ssn_valid("666-12-3456")
    assert aadhaar_valid("2341 2341 2346") and not aadhaar_valid("2341 2341 2345")


@pytest.mark.parametrize("text,rule", [
    ("pay with 4111-1111-1111-1111 today", "credit_card_number"),
    ("iban GB82 WEST 1234 5698 7654 32", "iban"),
    ("aadhaar 2341 2341 2346", "aadhaar_number"),
    ("PAN ABCPK1234Z", "indian_pan"),
    ("ssn 123-45-6789", "us_ssn"),
    ("call +91 98765 43210", "phone_number"),
    ("OPENAI=sk-proj-" + "a" * 40, "openai_api_key"),
    ("key sk-ant-" + "b" * 40, "anthropic_api_key"),
    ("https://hooks.slack.com/services/T0000/B0000/" + "x" * 24, "chat_webhook_url"),
])
def test_new_rules_fire(text, rule):
    assert rule in rules_hit(text)


@pytest.mark.parametrize("text", [
    "order 4111 1111 1111 1112",       # Luhn-invalid
    "build 1234 5678 9012",             # no Aadhaar checksum / starts with 1
    "version 2.3.4 released 2026-10-03",
    "sk-ant-short",
])
def test_lookalikes_do_not_fire(text):
    assert not ({"credit_card_number", "aadhaar_number", "anthropic_api_key", "openai_api_key"} & rules_hit(text))


def test_first_invalid_match_does_not_hide_a_later_valid_one():
    assert "credit_card_number" in rules_hit("ref 4111 1111 1111 1112 then 4111 1111 1111 1111")


def test_every_rule_maps_to_mitre():
    assert all(rule.mitre for rule in load_rules())


def test_unknown_validator_rule_is_skipped(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("rules:\n  - id: x\n    category: c\n    regex: 'a'\n    base_severity: 1\n    validator: nope\n")
    assert load_rules(p) == []
